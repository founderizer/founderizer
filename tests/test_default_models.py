"""The owner's default model and effort for each AI provider (owner feature default_models, UI-API.md 1.108).

His words, 9 November 2026: "we should be able to choose the default model and reasoning effort for each agent,
depending on the ai provider. There should be a default for each somewhere under settings, and then each agent can be
changed individually". It is the runtime fact default_model of team.json; the hub checks it against the model lists
that the agents' machines report, and each helper gives it to the new sessions of an agent without its own values."""
import json
import os
import shutil
import tempfile
import time
import unittest
import unittest.mock
import uuid

import fleet
from leftovers import scratch_home
import hub
import lifecycle
import threads
import test_costs

LUNA = {"model": "gpt-6-luna", "display_name": "GPT-6-Luna", "default": True,
        "efforts": ["low", "medium", "high", "xhigh", "max"], "default_effort": "medium"}
TERRA = {"model": "gpt-5.6-terra", "display_name": "GPT-5.6-Terra", "default": False,
         "efforts": ["low", "medium", "high", "xhigh", "max", "ultra"], "default_effort": "low"}
CLAUDE = [{"model": m, "display_name": m.capitalize(), "default": False,
           "efforts": ["low", "medium", "high", "xhigh", "max"], "default_effort": None}
          for m in ("fable", "opus", "sonnet")]


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def reading(runtime, options, at=None, ok=True):
    return {"runtime": runtime, "ok": ok, "read_at": at or time.time(), "other_names": runtime == "claude",
            "source": "test", "error": None, "options": options}


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Choices, Sessions):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Choices(test_costs.Base):
    """The hub's half: the choices it offers, the check of a default, and where it shows."""

    def settings(self, **body):
        return self.request("/ui/settings", dict(request_id=str(uuid.uuid4()), db="test-generation", **body))

    def status(self, agent, features=("default_models",), **readings):
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps(dict(readings, features=list(features))), hub.now()))

    def default(self, runtime, model, effort):
        return self.settings(runtime_facts={runtime: {"default_model": {"model": model, "effort": effort}}})

    def test_the_owner_sets_a_default_for_each_provider_and_takes_it_back(self):
        self.status("lead", models=reading("claude", CLAUDE))
        self.status("solo", models=reading("codex", [LUNA, TERRA]))
        code, page = self.request("/ui/settings?db=test-generation")
        self.assertEqual(code, 200, page)
        self.assertEqual([o["model"] for o in page["models"]["claude"]], ["fable", "opus", "sonnet"])
        self.assertEqual([o["model"] for o in page["models"]["codex"]], ["gpt-6-luna", "gpt-5.6-terra"])
        self.assertEqual(page["runtime_facts"]["claude"]["default_model"], {"value": None, "default": None,
                                                                            "set": False})
        code, receipt = self.default("claude", "opus", "high")
        self.assertEqual((code, receipt["changed"]), (200, ["claude.default_model"]), receipt)
        self.assertEqual(self.origin_team()["runtime_facts"],
                         {"claude": {"default_model": {"model": "opus", "effort": "high"}}})
        self.assertEqual(lifecycle.facts_now(hub.TEAM, "claude")["default_model"], {"model": "opus", "effort": "high"})
        code, team = self.request("/ui/team?db=test-generation")
        self.assertEqual((code, team["default_models"]), (200, {"claude": {"model": "opus", "effort": "high"}}), team)
        code, receipt = self.default("codex", None, "xhigh")         # the list's default model, at another effort
        self.assertEqual(code, 200, receipt)
        code, receipt = self.settings(runtime_facts={"claude": {"default_model": None}})
        self.assertEqual((code, receipt["changed"]), (200, ["claude.default_model"]), receipt)
        self.assertEqual(self.origin_team()["runtime_facts"],
                         {"codex": {"default_model": {"model": None, "effort": "xhigh"}}})
        self.assertEqual(self.request("/ui/team?db=test-generation")[1]["default_models"],
                         {"codex": {"model": None, "effort": "xhigh"}})

    def test_the_hub_refuses_a_default_that_no_server_can_give(self):
        self.status("lead", models=reading("claude", CLAUDE))
        self.status("solo", models=reading("codex", [LUNA, TERRA]))
        for runtime, model, effort, words in (
                ("grok", None, "high", "Grok takes no model"),
                ("claude", "opus-4", None, "opus-4 is not a model of Claude Code on any server"),
                ("claude", "opus", "ultra", "ultra is not an effort of opus"),
                ("codex", None, "ultra", "ultra is not an effort of the default model of Codex"),
                ("codex", "gpt-7", "low", "gpt-7 is not a model of Codex")):
            code, data = self.default(runtime, model, effort)
            self.assertEqual(code, 409, (runtime, model, effort, data))
            self.assertIn(words, data["error"])
        self.assertNotIn("runtime_facts", self.origin_team())
        for model, effort in (("claude-opus-5-5", "max"), (None, "high")):      # a full name; Claude's own model
            self.assertEqual(self.default("claude", model, effort)[0], 200, (model, effort))
        self.assertEqual(self.default("codex", "gpt-5.6-terra", "ultra")[0], 200)
        for bad in ({"model": "opus"}, {"model": "two words", "effort": None}, {"model": None, "effort": 5}, "opus"):
            self.assertEqual(self.settings(runtime_facts={"claude": {"default_model": bad}})[0], 400, bad)

    def test_no_reading_no_default_and_a_desktop_reading_is_codex_s(self):
        """A runtime that no server reports cannot take a default; a Claude agent's desktop (screen) reading is a
        Codex list, and a failed or a foreign one gives nothing."""
        code, data = self.default("codex", "gpt-6-luna", None)
        self.assertEqual(code, 409, data)
        self.assertIn("No server reports the models of Codex yet", data["error"])
        self.status("hand", models=reading("claude", CLAUDE), screen_models=reading("codex", [LUNA, TERRA]))
        self.status("solo", models=reading("claude", CLAUDE))       # not the runtime it runs: a switch not loaded
        self.status("lead", models=reading("claude", CLAUDE, ok=False))
        choices = hub.model_choices()
        self.assertEqual(sorted(choices), ["claude", "codex"])
        self.assertEqual([o["model"] for o in choices["codex"]], ["gpt-6-luna", "gpt-5.6-terra"])
        self.assertEqual(self.default("codex", "gpt-6-luna", None)[0], 200)

    def test_two_lists_of_one_runtime_merge_by_model(self):
        self.status("lead", models=reading("claude", CLAUDE[:2]))
        self.status("hand", models=reading("claude", [dict(CLAUDE[1], efforts=["low", "ultra"]), CLAUDE[2]]))
        choices = {o["model"]: o for o in hub.model_choices()["claude"]}      # each reading's order, agent by agent
        self.assertEqual(list(choices), ["opus", "sonnet", "fable"])
        self.assertEqual(choices["opus"]["efforts"], ["low", "ultra", "medium", "high", "xhigh", "max"])

    def test_an_agent_s_effort_without_its_own_model_is_checked_against_the_model_its_sessions_get(self):
        """offered(): the owner's default model where the agent's list offers it, else the list's default, else
        (Claude, whose list marks none) any model's efforts."""
        self.status("solo", models=reading("codex", [LUNA, TERRA]))
        self.status("lead", models=reading("claude", CLAUDE))
        with self.assertRaises(hub.Refusal):
            hub.offered("solo", None, "ultra")              # gpt-6-luna has no ultra
        hub.offered("lead", None, "high")                   # Claude's own model: any model's efforts
        self.assertEqual(self.default("codex", "gpt-5.6-terra", None)[0], 200)
        hub.offered("solo", None, "ultra")                  # the default model offers it
        self.assertEqual(self.default("codex", "gpt-9", None)[0], 409)

    def test_a_failed_an_old_and_a_foreign_reading_give_no_choice(self):
        """model_readings: only good readings at most MODELS_MAX_AGE old, of the runtime that the agent runs (a switch
        that its helper has not loaded reads the old one), and for Codex also the desktop readings."""
        haiku = dict(CLAUDE[0], model="haiku", display_name="Haiku")
        old = time.time() - hub.MODELS_MAX_AGE - 60
        self.status("manager", models=reading("claude", [haiku], ok=False))
        self.status("lead", models=reading("claude", [dict(haiku, model="fable-2")], at=old))
        self.status("hand", models=reading("claude", CLAUDE), screen_models=reading("codex", [dict(LUNA, default=False)]))
        self.status("solo", models=reading("claude", [dict(haiku, model="sonnet-9")]),       # solo runs Codex
                    screen_models=reading("codex", [TERRA]))                               # a desktop list counts
        choices = hub.model_choices()
        self.assertEqual([o["model"] for o in choices["claude"]], ["fable", "opus", "sonnet"])
        self.assertEqual([o["model"] for o in choices["codex"]], ["gpt-6-luna", "gpt-5.6-terra"])
        self.status("lead", models=reading("codex", [LUNA]))         # lead runs Claude: a Codex list is not its own
        self.assertEqual([o["default"] for o in hub.model_choices()["codex"]], [False, False])
        self.status("solo", models=reading("codex", [LUNA]), screen_models=reading("codex", [TERRA]))
        self.assertEqual([o["default"] for o in hub.model_choices()["codex"]], [True, False])    # one reading marks it

    def test_the_hub_checks_a_desktop_effort_against_the_codex_default_where_the_helper_takes_it(self):
        self.status("hand", features=(), models=reading("claude", CLAUDE), screen_models=reading("codex", [LUNA, TERRA]))
        self.assertEqual(self.default("codex", "gpt-5.6-terra", None)[0], 200)
        self.assertEqual(self.default("claude", "sonnet", None)[0], 200)        # not the screen list's default
        with self.assertRaises(hub.Refusal):                # an older helper runs the list's default: no ultra
            hub.offered("hand", None, "ultra", reading="screen_models")
        self.status("hand", models=reading("claude", CLAUDE), screen_models=reading("codex", [LUNA, TERRA]))
        hub.offered("hand", None, "ultra", reading="screen_models")
        with self.assertRaises(hub.Refusal):
            hub.offered("hand", "gpt-6-luna", "ultra", reading="screen_models")

    def test_claude_names_its_models_as_he_reads_them(self):
        text = ("Options:\n  --model <model>  Model for the current session. Provide an alias for the latest model "
                "(e.g. 'sonnet' or 'opus') or a model's full name (e.g. 'claude-sonnet-5-5').\n"
                "  --effort <level>  Effort level for the current session (low, medium, high, xhigh, max)\n")
        options, error = lifecycle.claude_model_list(text)
        self.assertIsNone(error)
        self.assertEqual([(o["model"], o["display_name"]) for o in options],
                         [("sonnet", "Sonnet"), ("opus", "Opus"), ("claude-sonnet-5-5", "Claude-sonnet-5-5")])

    def test_the_owner_mcp_names_the_fact(self):
        import owner_mcp
        text = next(t for t in owner_mcp.tools() if t["name"] == "save_settings")["description"]
        self.assertIn("default_model", text)
        self.assertIn("default_model", lifecycle.EDITABLE_FACTS)
        self.assertIn("default_models", hub.UI_FEATURES)
        self.assertIn("default_models", lifecycle.FEATURES)


class Sessions(unittest.TestCase):
    """The helper's half: what a new session starts with (fleet.run_settings, Helper.runner_conf)."""

    CODEX = {"role": "worker", "runtime": "codex", "start": "codex --no-daemon {prompt}"}
    LISTED = reading("codex", [LUNA, TERRA])

    def run_with(self, default, conf=None, models=None, listed=True):
        return fleet.run_settings(conf or self.CODEX, self.LISTED if models is None else models, default, listed)

    def test_its_own_then_the_owner_s_default_then_the_list_s(self):
        self.assertEqual(self.run_with(None), {"model": "gpt-6-luna", "effort": "medium"})       # as before
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": None}),
                         {"model": "gpt-5.6-terra", "effort": "low"})         # that model's own default effort
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": "ultra"}),
                         {"model": "gpt-5.6-terra", "effort": "ultra"})
        self.assertEqual(self.run_with({"model": None, "effort": "xhigh"}), {"model": "gpt-6-luna", "effort": "xhigh"})
        self.assertEqual(self.run_with({"model": None, "effort": "ultra"}),     # luna has none: its own default
                         {"model": "gpt-6-luna", "effort": "medium"})
        self.assertEqual(self.run_with({"model": "gpt-9", "effort": "high"}),   # not offered on this machine
                         {"model": "gpt-6-luna", "effort": "high"})
        own = dict(self.CODEX, model="gpt-6-luna", effort="low")
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": "max"}, own),
                         {"model": "gpt-6-luna", "effort": "low"})
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": "max"}, dict(self.CODEX, effort="low")),
                         {"model": "gpt-5.6-terra", "effort": "low"})
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": "max"}, dict(self.CODEX, model="gpt-6-luna")),
                         {"model": "gpt-6-luna", "effort": "max"})

    def test_an_own_effort_that_the_default_model_does_not_offer_gives_way(self):
        """An agent's own effort with no model was checked against the default model of that day (hub.offered); a
        later default model without it must not start every session with an effort the model refuses."""
        own = dict(self.CODEX, effort="ultra")
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": None}, own),
                         {"model": "gpt-5.6-terra", "effort": "ultra"})
        self.assertEqual(self.run_with({"model": "gpt-6-luna", "effort": None}, own),
                         {"model": "gpt-6-luna", "effort": "medium"})
        self.assertEqual(self.run_with({"model": "gpt-6-luna", "effort": "high"}, own),
                         {"model": "gpt-6-luna", "effort": "high"})
        self.assertEqual(self.run_with(None, own), {"model": "gpt-6-luna", "effort": "medium"})       # cleared
        self.assertEqual(self.run_with(None, own, listed=False), {"model": None, "effort": None})   # the runner's
        self.assertEqual(self.run_with(None, dict(own, model="gpt-5.6-terra")),                     # its own model:
                         {"model": "gpt-5.6-terra", "effort": "ultra"})                             # as it chose

    def test_claude_takes_a_default_effort_with_its_own_model_and_a_full_name(self):
        claude = {"role": "worker", "runtime": "claude"}
        listed = reading("claude", CLAUDE)
        self.assertEqual(self.run_with(None, claude, listed), {"model": None, "effort": None})
        self.assertEqual(self.run_with({"model": "opus", "effort": "high"}, claude, listed),
                         {"model": "opus", "effort": "high"})
        self.assertEqual(self.run_with({"model": None, "effort": "high"}, claude, listed),
                         {"model": None, "effort": "high"})
        self.assertEqual(self.run_with({"model": "claude-opus-5-5", "effort": "max"}, claude, listed),
                         {"model": "claude-opus-5-5", "effort": "max"})
        self.assertEqual(self.run_with({"model": "opus", "effort": "ultra"}, claude, listed),
                         {"model": "opus", "effort": None})
        self.assertEqual(fleet.model_flags(dict(claude, **self.run_with({"model": "opus", "effort": "high"}, claude,
                                                                          listed))), "--model opus --effort high")

    def test_without_a_good_reading_of_its_runtime_the_default_is_not_given(self):
        default = {"model": "gpt-5.6-terra", "effort": "high"}
        for models in (None, dict(self.LISTED, ok=False), dict(self.LISTED, runtime="claude")):
            self.assertEqual(fleet.run_settings(self.CODEX, models, default), {"model": None, "effort": None})
        self.assertEqual(fleet.run_settings(dict(self.CODEX, model="gpt-6-luna"), None, default),
                         {"model": "gpt-6-luna", "effort": None})

    def test_a_runner_gets_only_its_own_or_the_owner_s_default(self):
        """An app-server runner reads the account's list itself (screen_runner.default_model): the helper gives it
        no list default, and a runner given a model takes no effort from its list, so the default's model comes with
        an effort."""
        self.assertEqual(self.run_with(None, listed=False), {"model": None, "effort": None})
        self.assertEqual(self.run_with({"model": "gpt-5.6-terra", "effort": None}, listed=False),
                         {"model": "gpt-5.6-terra", "effort": "low"})
        self.assertEqual(self.run_with({"model": None, "effort": "high"}, listed=False),
                         {"model": None, "effort": "high"})
        self.assertEqual(self.run_with(None, dict(self.CODEX, model="gpt-5.6-terra"), listed=False),
                         {"model": "gpt-5.6-terra", "effort": None})          # as before: its own model alone

    def test_a_desktop_task_takes_the_codex_default_by_the_desktop_reading(self):
        conf = {"role": "worker", "runtime": "claude", "screen_command": "codex app-server", "screen": {}}
        helper = fleet.Helper("ivy", conf)
        helper.lifecycle = unittest.mock.Mock(models=None, screen_models=self.LISTED)
        defaults = {"codex": {"model": "gpt-5.6-terra", "effort": "high"}, "claude": {"model": "opus", "effort": "low"}}
        with unittest.mock.patch.object(fleet, "owner_default", lambda runtime: defaults.get(runtime)):
            chosen = helper.runner_conf("screen")
            self.assertEqual(chosen["screen"], {"model": "gpt-5.6-terra", "effort": "high"})
            self.assertEqual(chosen["runtime"], "claude")
            self.assertIs(helper.conf["screen"], conf["screen"])      # a copy: the reported settings stay its own
            self.assertIn("--model gpt-5.6-terra --effort high",
                          fleet.session_command("ivy", chosen, "Look", task="T-1", needs="screen", attempt=1,
                                                generation="g", session="s"))
            self.assertEqual(helper.requested_now(screen=True), {"model": "gpt-5.6-terra", "effort": "high"})
            own = fleet.Helper("ivy", dict(conf, screen={"model": "gpt-6-luna", "effort": None}))
            own.lifecycle = helper.lifecycle
            self.assertEqual(own.runner_conf("screen")["screen"], {"model": "gpt-6-luna", "effort": "high"})
        plain = fleet.Helper("leo", {"role": "worker", "runtime": "claude"})
        self.assertEqual(plain.requested_now(screen=True), {})

    def kit(self, default):
        folder = tempfile.mkdtemp(prefix="fleet-default-models-")
        self.addCleanup(shutil.rmtree, folder, True)
        with open(os.path.join(folder, "team.json"), "w") as f:
            json.dump({"agents": {}, "runtime_facts": {"claude": {"default_model": default}}}, f)
        return unittest.mock.patch.object(fleet, "KIT", folder), folder

    def test_the_helper_s_sessions_take_the_default_from_its_checkout(self):
        """Helper.runs: every terminal session builder takes run_conf(), so a task, a chat, a conversation and the
        manager start with the owner's default, read from team.json in this checkout."""
        claude = reading("claude", CLAUDE)
        conf = {"role": "worker", "runtime": "claude", "start": "claude --permission-mode dontAsk {chrome} {settings} "
                                                                "{prompt}"}
        moved, folder = self.kit({"model": "opus", "effort": "high"})
        with moved:
            self.assertEqual(fleet.owner_default("claude"), {"model": "opus", "effort": "high"})
            self.assertIsNone(fleet.owner_default("codex"))
            helper = fleet.Helper("mia", conf)
            helper.lifecycle = unittest.mock.Mock(models=claude, screen_models=None, read_models=lambda force=False: claude)
            self.assertEqual(helper.runs(), {"model": "opus", "effort": "high"})
            self.assertEqual(fleet.model_flags(helper.run_conf()), "--model opus --effort high")
            self.assertEqual(helper.requested_now(), {"model": "opus", "effort": "high"})
            with open(os.path.join(folder, "team.json"), "w") as f:         # the owner's change, read at the next start
                json.dump({"agents": {}, "runtime_facts": {"claude": {"default_model": {"model": "sonnet",
                                                                                        "effort": None}}}}, f)
            self.assertEqual(helper.runs(), {"model": "sonnet", "effort": None})
            own = fleet.Helper("mia", dict(conf, effort="low"))
            own.lifecycle = helper.lifecycle
            self.assertEqual(own.runs(), {"model": "sonnet", "effort": "low"})

    def test_a_codex_runner_task_gets_the_default_and_its_records_name_what_it_got(self):
        conf = {"role": "worker", "runtime": "codex", "start": lifecycle.APP_SERVER}
        helper = fleet.Helper("vps", conf)
        helper.lifecycle = unittest.mock.Mock(models=self.LISTED, screen_models=None)
        helper.model_list = self.LISTED
        defaults = {"codex": {"model": "gpt-5.6-terra", "effort": None}}
        with unittest.mock.patch.object(fleet, "owner_default", lambda runtime: defaults.get(runtime)):
            self.assertTrue(lifecycle.app_server_task(conf, "none"))
            chosen = helper.runner_conf("none")
            self.assertEqual((chosen["model"], chosen["effort"]), ("gpt-5.6-terra", "low"))
            feed = helper.tailer.feed(("T-1", "g", 1, "s", "codex_app", "none"))
            self.assertEqual(feed.translator.requested, {"model": "gpt-5.6-terra", "effort": "low"})
            defaults["codex"] = None
            self.assertEqual({k: helper.runner_conf("none")[k] for k in ("model", "effort")},
                             {"model": None, "effort": None})       # the runner's own list default, read at its start
            feed = helper.tailer.feed(("T-2", "g", 1, "s", "codex_app", "none"))
            self.assertEqual(feed.translator.requested, {"model": None, "effort": None})
            self.assertEqual(helper.tailer.feed(("T-3", "g", 1, "s")).translator.requested,
                             {"model": "gpt-6-luna", "effort": "medium"})    # a terminal session: the list's default

    def test_setting_a_default_restarts_no_running_session_and_every_other_change_still_does(self):
        """reuse_runs: a session on what the agent would run without the default keeps running when one appears; a
        change of the agent's own settings (a cleared one too), a later change of the default, a model that its list no
        longer offers, and a Codex session on its configuration's model where the list gives one start it again."""
        claude = reading("claude", CLAUDE)
        defaults = {"claude": {"model": "opus", "effort": "high"}}
        helper = fleet.Helper("mia", {"role": "worker", "runtime": "claude"})
        helper.model_list = claude

        def started(model, effort, runtime="claude"):
            return {"runtime": runtime, "model": model, "effort": effort, "account": "anthropic:" + "a" * 32}

        def kept(who, model, effort, runtime="claude"):
            begun = started(model, effort, runtime)
            return lifecycle.session_reuse(runtime, (100, 90, time.time() - 5, 3600), begun,
                                           who.reuse_runs(begun, runtime), None)[0]
        with unittest.mock.patch.object(fleet, "owner_default", lambda runtime: defaults.get(runtime)), \
                unittest.mock.patch.object(fleet, "account_now", return_value="anthropic:" + "a" * 32):
            self.assertTrue(kept(helper, None, None))               # Claude's own: the first default restarts nothing
            self.assertTrue(kept(helper, "opus", "high"))           # on the default itself
            self.assertFalse(kept(helper, "sonnet", "low"))         # an earlier default, or an own model now cleared
            self.assertFalse(kept(helper, "opus", None))            # a default effort that came since
            self.assertEqual(helper.reuse_runs(None, "claude")["model"], "opus")
            own = fleet.Helper("mia", {"role": "worker", "runtime": "claude", "model": "sonnet", "effort": "max"})
            own.model_list = claude
            self.assertFalse(kept(own, None, None))                 # its own change starts it again
            self.assertTrue(kept(own, "sonnet", "max"))
            helper.model_list = dict(claude, ok=False)              # no list to judge by: it keeps what it started with
            self.assertTrue(kept(helper, "opus-old", "max"))
            codex = fleet.Helper("vps", self.CODEX)
            codex.model_list = self.LISTED
            for model, effort, want in ((None, None, False), ("gpt-6-luna", "medium", True), ("gpt-4", None, False)):
                self.assertEqual(kept(codex, model, effort, "codex"), want, model)

    def test_the_setup_check_reads_an_own_effort_against_the_default_model(self):
        conf = {"role": "worker", "runtime": "codex", "effort": "ultra"}
        moved, folder = self.kit(None)
        with open(os.path.join(folder, "team.json"), "w") as f:
            json.dump({"agents": {}, "runtime_facts": {"codex": {"default_model": {"model": "gpt-5.6-terra",
                                                                                     "effort": None}}}}, f)
        life = lifecycle.Lifecycle(folder, "vps", conf, post=lambda *a, **k: None, busy=lambda: False)
        self.assertEqual(life.model_item(self.LISTED)[2], "ok")
        bare = tempfile.mkdtemp(prefix="fleet-default-models-")
        self.addCleanup(shutil.rmtree, bare, True)
        self.assertEqual(lifecycle.Lifecycle(bare, "vps", conf, post=lambda *a, **k: None,
                                             busy=lambda: False).model_item(self.LISTED)[2], "failed")

    def test_the_records_name_what_the_helper_passed(self):
        """threads.Tailer takes a function: the requested model of a session's records is what it got at its start,
        the owner's default included."""
        asked = {"model": "opus", "effort": "high"}
        tailer = threads.Tailer("claude", lambda: [], lambda batch: None, requested=lambda: asked)
        feed = tailer.feed(("T-1", "g", 1, "s"))
        self.assertEqual(feed.translator.requested, asked)
        self.assertEqual(feed.translator.model_record("claude-opus-5-5", "high")[0]["requested_model"], "opus")
        still = threads.Tailer("claude", lambda: [], lambda batch: None, requested={"model": None, "effort": None})
        self.assertEqual(still.feed(("T-2", "g", 1, "s")).translator.requested, {"model": None, "effort": None})


if __name__ == "__main__":
    unittest.main()
