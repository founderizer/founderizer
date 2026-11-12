#!/usr/bin/env python3
"""The price file of the models that an OpenCode or a Grok Build session runs (prices/models.json), made from the
public list of https://models.dev/api.json.

    python3 prices.py                 # read the list, and write prices/models.json of this checkout
    python3 prices.py --from FILE     # the same, from a copy of the list
    python3 prices.py --print         # print the file, and write nothing

A person runs it when a pin of onboard.PINNED moves, reads the difference and commits the file. No helper and no hub
calls that address: lifecycle.py loads the file of its own checkout as the `token_weights` of the two runtimes, and a
file that is missing or wrong gives no prices and never an error (lifecycle.price_file).

The file maps a model key to its list prices in dollars for a million tokens, {input, cache_read, cache_write,
output}, with "default", at most 50 keys (lifecycle.weights_check). lifecycle.token_price gives a session's model the
entry whose key is the longest part of its name, so a key here is a model FAMILY, and FAMILIES names each one with
the model of the list whose price it takes. The hub keeps these prices, and not a program's own cost number, so that
one period compares with another. On an account with a plan they are weights, not money spent.

The owner's own model server costs nothing: OpenCode's configuration names it `own`, so each of its models is
`own/<name>`, and the key "own/" has four zeros. A key that ends in "/" matches only the start of a model's name and
wins over each other key (lifecycle.token_price).

No helper and no hub runs this tool. It is published with the fleet's code, as its file and pins.py are.
"""
import argparse
import json
import os
import sys
import urllib.request

import lifecycle

SOURCE = "https://models.dev/api.json"
CLIENT = "Founderizer-Fleet/1 (prices)"
HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "prices", "models.json")
LIMIT = 64 * 1024 * 1024
FREE = {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0}
# (the key of the file, the provider of the list, its model whose price the key takes). A longer key wins, so a
# family's own key is its fallback, and a model with another price has a longer key of its own.
FAMILIES = (
    ("default", "opencode-go", "kimi-k3.1-pro"),
    # Gemini, by key (the account provider `google`)
    ("gemini", "google", "gemini-pro-latest"),
    ("gemini-4", "google", "gemini-4-carbon"),
    ("gemini-3", "google", "gemini-flash-latest"),
    ("gemini-3.1-pro", "google", "gemini-3.1-pro-preview"),
    ("gemini-3.5-flash", "google", "gemini-3.5-flash"),
    ("gemini-3.5-flash-lite", "google", "gemini-3.5-flash-lite"),
    ("gemini-3.1-flash-lite", "google", "gemini-3.1-flash-lite"),
    ("gemini-3-flash", "google", "gemini-3-flash-preview"),
    ("gemini-flash", "google", "gemini-flash-latest"),
    ("gemini-flash-lite", "google", "gemini-flash-lite-latest"),
    ("gemini-2.5-pro", "google", "gemini-2.5-pro"),
    ("gemini-2.5-flash", "google", "gemini-2.5-flash"),
    ("gemini-2.5-flash-lite", "google", "gemini-2.5-flash-lite"),
    # Grok, by key (the account provider `xai`)
    ("grok", "xai", "grok-4.7"),
    ("grok-4.5", "xai", "grok-4.5"),
    ("grok-4.3", "xai", "grok-4.3"),
    ("grok-4.20", "xai", "grok-4.20-0309-reasoning"),
    ("grok-build", "xai", "grok-build-0.1"),
    # The open models, at the sellers of several makers
    ("deepseek", "opencode-go", "deepseek-v4-pro"),
    ("deepseek-v4.1-flash", "opencode-go", "deepseek-v4.1-flash"),
    ("glm", "opencode-go", "glm-5.3"),
    ("glm-5.3-flash", "opencode-go", "glm-5.3-flash"),
    ("kimi", "opencode-go", "kimi-k3.1-pro"),
    ("kimi-k3", "opencode-go", "kimi-k3"),
    ("kimi-k3.1-pro", "opencode-go", "kimi-k3.1-pro"),
    ("kimi-k2", "opencode-go", "kimi-k2.7-code"),
    ("qwen", "opencode-go", "qwen3.7-plus"),
    ("qwen3.8-max", "opencode-go", "qwen3.8-max"),
    ("qwen3.8-flash", "opencode-go", "qwen3.8-flash"),
    ("minimax", "opencode-go", "minimax-m3"),
    ("minimax-m3.1-flash", "opencode-go", "minimax-m3.1-flash"),
    ("mimo", "opencode-go", "mimo-v2.6-pro"),
    ("gpt-oss", "ollama-cloud", "gpt-oss:120b"),
    ("gemma", "ollama-cloud", "gemma4:31b"),
    ("mistral", "ollama-cloud", "mistral-large-4"),
    ("nemotron", "ollama-cloud", "nemotron-3-ultra"),
    ("muse-spark", "ollama-cloud", "muse-spark-open"),
    ("llama", "openrouter", "meta-llama/llama-4-maverick"),
    # The models of the two first providers, where a seller offers them
    ("claude-fable", "openrouter", "anthropic/claude-fable-5.2"),
    ("claude-opus", "openrouter", "anthropic/claude-opus-5.5"),
    ("claude-sonnet", "openrouter", "anthropic/claude-sonnet-5.5"),
    ("claude-haiku", "openrouter", "anthropic/claude-haiku-5.5"),
    ("gpt", "openrouter", "openai/gpt-6.1-sol"),
    ("gpt-6-astra", "openrouter", "openai/gpt-6-astra"),
    ("gpt-6.1-terra", "openrouter", "openai/gpt-6.1-terra"),
    ("gpt-6-luna", "openrouter", "openai/gpt-6-luna"),
)
OWN = "own/"        # the owner's own model server, in OpenCode's configuration


class Refused(Exception):
    """The list does not give what the file needs."""


def price(listed, provider, model):
    """One model's prices from the list, in the file's four kinds. A model with no price for a cache read pays the
    input price for it, and one with no price for a cache write pays the input price too: a provider charges no less
    for a write than for input."""
    row = ((listed.get(provider) or {}).get("models") or {}).get(model) if isinstance(listed, dict) else None
    cost = row.get("cost") if isinstance(row, dict) else None
    number = lambda value: isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 10000
    if not isinstance(cost, dict) or not number(cost.get("input")) or not number(cost.get("output")):
        raise Refused(f"the list has no price for {provider}/{model}")
    read = cost["cache_read"] if number(cost.get("cache_read")) else cost["input"]
    write = cost["cache_write"] if number(cost.get("cache_write")) and cost["cache_write"] >= cost["input"] \
        else cost["input"]
    return {"input": cost["input"], "cache_read": read, "cache_write": write, "output": cost["output"]}


def made(listed, families=FAMILIES):
    """The price file from the list: each family's key with its model's prices, and the owner's own server at 0."""
    prices = {key: price(listed, provider, model) for key, provider, model in families}
    prices[OWN] = dict(FREE)
    if "default" not in prices:
        raise Refused("the families name no default")
    try:
        return lifecycle.weights_check(prices)
    except ValueError as e:
        raise Refused(f"the file {e}") from None


def text(prices):
    return json.dumps(prices, indent=1, sort_keys=True) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make prices/models.json from the public model list of models.dev")
    ap.add_argument("--from", dest="source", help="a copy of the list, in the place of the address")
    ap.add_argument("--print", action="store_true", help="print the file and write nothing")
    args = ap.parse_args(argv)
    try:
        if args.source:
            with open(args.source, "rb") as f:
                raw = f.read(LIMIT)
        else:
            with urllib.request.urlopen(urllib.request.Request(SOURCE, headers={"User-Agent": CLIENT}),
                                        timeout=60) as r:
                raw = r.read(LIMIT)
        prices = made(json.loads(raw))
    except (OSError, ValueError, Refused) as e:
        print(f"prices.py: {e if isinstance(e, Refused) else type(e).__name__ + ': ' + str(e)[:200]}", file=sys.stderr)
        return 1
    if args.print:
        sys.stdout.write(text(prices))
        return 0
    os.makedirs(os.path.dirname(FILE), exist_ok=True)
    with open(FILE + ".part", "w", encoding="utf-8") as f:
        f.write(text(prices))
    os.replace(FILE + ".part", FILE)
    print(f"{FILE}: {len(prices)} keys")
    return 0


if __name__ == "__main__":
    sys.exit(main())
