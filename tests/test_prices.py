"""The price file of the models that the two ACP programs run (prices/models.json), its safe load in lifecycle.py, the
rule of lifecycle.token_price for the owner's own model server, and prices.py, the tool that makes the file from a
public list (the AI providers build spec, section 3.7). No network: the list is a stand-in.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import lifecycle
import prices


class Prices(unittest.TestCase):
    """The price file of the models of the two ACP programs (the AI providers spec, section 3.7)."""
    LISTED = {"google": {"models": {"gemini-pro": {"cost": {"input": 2, "output": 12, "cache_read": 0.2}},
                                    "free": {"cost": {"input": 0, "output": 0}}, "unpriced": {}}},
              "seller": {"models": {"deepseek-v9": {"cost": {"input": 0.5, "output": 1.5, "cache_write": 0.1}}}}}
    FAMILIES = (("default", "google", "gemini-pro"), ("gemini", "google", "gemini-pro"),
                ("deepseek", "seller", "deepseek-v9"))

    def test_a_price_file_that_is_missing_or_wrong_gives_no_prices_and_never_an_error(self):
        tmp = Path(tempfile.mkdtemp(prefix="fleet-prices-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        good = {"default": {"input": 1, "cache_read": 0.1, "cache_write": 1, "output": 2}}
        step = lambda day, **more: dict(good["default"], **{"from": day}, **more)
        later = lambda *steps: json.dumps({"default": dict(good["default"], later=list(steps))})
        cases = {"good.json": json.dumps(good), "broken.json": "{\"default\": ", "list.json": "[1, 2]",
                 "shape.json": json.dumps({"default": {"input": 1}}), "empty.json": "{}", "null.json": "null",
                 "many.json": json.dumps({f"m{n}": good["default"] for n in range(lifecycle.PRICE_KEYS + 1)}),
                 "long.json": json.dumps(dict(good, pad="x" * 300000)),
                 # a later price with no day, a day that is no date, two in the wrong order, one that is not a list
                 "no-day.json": later(good["default"]), "no-date.json": later(step("2026-02-30")),
                 "order.json": later(step("2027-01-01"), step("2026-12-01")),
                 "same.json": later(step("2026-12-01"), step("2026-12-01")),
                 "nested.json": later(step("2026-12-01", later=[])), "one.json": json.dumps(
                     {"default": dict(good["default"], later=step("2026-12-01"))}),
                 "five.json": later(*[step(f"2027-0{n}-01") for n in range(1, lifecycle.LATER_PRICES + 2)]),
                 "price.json": later(dict(step("2026-12-01"), input="4")),
                 "minus.json": later(dict(step("2026-12-01"), output=-1))}
        for name, text in cases.items():
            (tmp / name).write_text(text)
        self.assertEqual(lifecycle.price_file(str(tmp / "good.json")), good)
        for name in [*list(cases)[1:], "no-such-file.json"]:
            self.assertIsNone(lifecycle.price_file(str(tmp / name)), name)
        (tmp / "folder.json").mkdir()
        self.assertIsNone(lifecycle.price_file(str(tmp / "folder.json")))
        # and lifecycle imports with each of them: `lifecycle.py may-take` runs at each move of a checkout
        kit = Path(lifecycle.__file__).resolve().parent
        for name in ("lifecycle.py", "onboard.py"):
            shutil.copy(kit / name, tmp / name)
        said = lambda: subprocess.run(
            [sys.executable, "-c", "import lifecycle; print([lifecycle.RUNTIMES[n]['token_weights'] is None "
                                   "for n in ('grok', 'opencode', 'claude', 'codex')])"],
            cwd=tmp, capture_output=True, text=True, timeout=60, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        for text in (None, cases["broken.json"], cases["shape.json"]):
            if text is not None:
                (tmp / "prices").mkdir(exist_ok=True)
                (tmp / "prices" / "models.json").write_text(text)
            answer = said()
            self.assertEqual((answer.returncode, answer.stdout.strip()), (0, "[True, True, False, False]"), answer.stderr)
        (tmp / "prices" / "models.json").write_text(cases["good.json"])
        self.assertEqual(said().stdout.strip(), "[False, False, False, False]")

    def test_the_file_of_this_checkout_prices_both_programs_and_the_owners_own_server_costs_nothing(self):
        file = lifecycle.price_file()
        self.assertIsNotNone(file)
        self.assertLessEqual(len(file), lifecycle.PRICE_KEYS)
        self.assertIn("default", file)
        self.assertEqual(file["own/"], {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0})
        for name in ("grok", "opencode"):
            self.assertEqual(lifecycle.RUNTIMES[name]["token_weights"], file)
            self.assertEqual(lifecycle.facts_now({}, name)["token_weights"], file)
        self.assertEqual(sorted(file), sorted([key for key, _, _ in prices.FAMILIES] + ["own/"]))

    def test_a_model_of_the_owners_own_server_costs_nothing_whatever_its_name_holds(self):
        """lifecycle.token_price took the longest key that is part of the name: own/deepseek-r1 took the price of a
        key "deepseek". A key that ends in / matches only the start of a name, and wins over each other key."""
        weights = {"default": {"input": 9}, "deepseek": {"input": 1}, "deepseek-r1": {"input": 2},
                   "own/": {"input": 0}, "seller/": {"input": 5}}
        price = lambda model: lifecycle.token_price(weights, model)["input"]
        self.assertEqual([price("own/deepseek-r1"), price("OWN/deepseek"), price("own/x")], [0, 0, 0])
        self.assertEqual([price("deepseek-r1"), price("deepseek-v4"), price("seller/deepseek-r1")], [2, 1, 5])
        self.assertEqual([price("known/own/deepseek-r1"), price("town/x"), price(None)], [2, 9, 9])
        # own/ costs nothing also on a runtime with no prices; every other model of one has no price
        self.assertEqual(lifecycle.token_price(None, "own/x"), dict.fromkeys(lifecycle.TOKEN_KINDS, 0))
        self.assertIsNone(lifecycle.token_price(None, "x"))
        real = lifecycle.price_file()
        self.assertEqual(lifecycle.token_price(real, "own/gemini-4-carbon"), real["own/"])
        self.assertEqual(lifecycle.token_price(real, "google/gemini-4-argon"), real["gemini-4"])
        self.assertEqual(lifecycle.token_price(real, "grok-4.7"), real["grok"])
        # the tables of the two first runtimes read as before
        claude = lifecycle.RUNTIMES["claude"]["token_weights"]
        self.assertEqual(lifecycle.token_price(claude, "claude-fable-5-2"), claude["fable"])
        self.assertEqual(lifecycle.token_price(claude, "claude-next"), claude["default"])

    def test_a_price_that_a_provider_announced_holds_from_its_day_by_itself(self):
        """Google's price of Gemini 4 Carbon doubles on 1 December 2026, and no run of prices.py comes that day: the
        file holds it now under "later", and token_price takes it from that day in UTC, for that model alone."""
        real = lifecycle.price_file()
        carbon = lambda day: lifecycle.token_price(real, "google/gemini-4-carbon", day)
        self.assertEqual(carbon("2026-11-30"), {"input": 2, "cache_read": 0.1, "cache_write": 2, "output": 10})
        self.assertEqual([carbon(day) for day in ("2026-12-01", "2027-06-01")],
                         [{"input": 4, "cache_read": 0.2, "cache_write": 4, "output": 20}] * 2)
        for day in ("2026-11-30", "2026-12-01"):
            self.assertEqual(lifecycle.token_price(real, "gemini-4-argon", day), real["gemini-4"])
            self.assertEqual(lifecycle.token_price(real, "google/gemini-4-neon", day)["input"], 3)
        # the newest price whose day has come, of several; with no day, today's
        weights = {"default": {"input": 1, "cache_read": 1, "cache_write": 1, "output": 1, "later": [
            dict.fromkeys(lifecycle.TOKEN_KINDS, 2) | {"from": "2026-12-01"},
            dict.fromkeys(lifecycle.TOKEN_KINDS, 3) | {"from": "2027-01-01"}]}}
        self.assertEqual(lifecycle.weights_check(weights), weights)
        price = lambda day: lifecycle.token_price(weights, "x", day)["input"]
        self.assertEqual([price("2026-11-30"), price("2026-12-31"), price("2027-01-01")], [1, 2, 3])
        # with no day, today's in UTC: 23:30 UTC on 30 November is 1 December in Madrid, and the price is still November's
        for at, want in ((1796081400, 1), (1796085000, 2)):         # 2026-11-30 23:30 and 2026-12-01 00:30 UTC
            with unittest.mock.patch.object(lifecycle.time, "time", lambda: at):
                self.assertEqual(lifecycle.token_price(weights, "x")["input"], want, at)
        self.assertEqual(set(lifecycle.token_price(weights, "x", "2026-12-01")), set(lifecycle.TOKEN_KINDS))

    def test_the_tool_makes_the_file_from_the_public_list_and_refuses_a_family_with_no_price(self):
        made = prices.made(self.LISTED, self.FAMILIES, {})
        self.assertEqual(made, {
            "default": {"input": 2, "cache_read": 0.2, "cache_write": 2, "output": 12},
            "gemini": {"input": 2, "cache_read": 0.2, "cache_write": 2, "output": 12},
            # no price for a cache read: the input's; a write below the input: the input's
            "deepseek": {"input": 0.5, "cache_read": 0.5, "cache_write": 0.5, "output": 1.5},
            "own/": {"input": 0, "cache_read": 0, "cache_write": 0, "output": 0}})
        self.assertEqual(json.loads(prices.text(made)), made)
        # a price that the provider announced goes under its key, with its day; LATER of no family is refused
        dated = prices.made(self.LISTED, self.FAMILIES, {"gemini": (("2026-12-01", {"input": 4, "cache_read": 0.4,
                                                                                    "cache_write": 4, "output": 24}),)})
        self.assertEqual(dated["gemini"]["later"], [{"from": "2026-12-01", "input": 4, "cache_read": 0.4,
                                                     "cache_write": 4, "output": 24}])
        self.assertNotIn("later", dated["default"])
        with self.assertRaises(prices.Refused):
            prices.made(self.LISTED, self.FAMILIES, {"grok": (("2026-12-01", made["gemini"]),)})
        for families in ((("default", "google", "unpriced"),), (("default", "google", "no-such-model"),),
                         (("default", "no-such-provider", "x"),), (("gemini", "google", "gemini-pro"),)):
            with self.assertRaises(prices.Refused):
                prices.made(self.LISTED, families, {})
        self.assertEqual(len({key for key, _, _ in prices.FAMILIES}), len(prices.FAMILIES))
        self.assertLessEqual(len(prices.FAMILIES) + 1, lifecycle.PRICE_KEYS)
        self.assertLessEqual(set(prices.LATER), {key for key, _, _ in prices.FAMILIES})


if __name__ == "__main__":
    unittest.main()
