"""Wake-up rules that agents manage themselves (owner corrections, 10 October 2026).

An agent creates, reads, edits, pauses, resumes and deletes its own wake-up rules with its Fleet tools, and the
fleet manager (the team's one "manager") does it for every agent, itself included. A rule is a trigger of owner API
1.7 and 1.8: the hub's scheduler, runs, admission, helper checks and transactions stay as they are, and there is no
second scheduler. This module holds only the new decisions. It has no database access and does not import the hub,
so its tests need no hub:

- authority: the hub's one authority function, authority(actor, target, action), decides every rule write, every
  read and every wake, and every task that a wake starts;
- the route of a wake-up: one inbox message for the fleet manager, or a task whose requester can see its result: the
  fleet manager directly, or a lead through a parent task in its own task session;
- saved check code: an agent writes a check as text; the hub keeps each version by its SHA-256 and never changes it,
  without a repository commit or an owner pin for each change;
- where saved code runs (plan P4): only on its own agent's machine, as that agent's user and with that agent's read
  keys, only where that agent's runtime already runs any command without asking (execution_grant), and only when
  that agent saved the code itself, so a check adds no capability. There is no other runner and no approval;
- what a check says (plan P4): one line for each item that needs the agent now, and the hub wakes the agent only for
  the lines that the last accepted run did not print (AUTONOMY.md 6.5). The older value form prints {"value",
  "summary"}; a value that matches its condition reads as one line that begins with the rule's own id (value_line),
  so it wakes once while the condition holds and again only after a quiet run, through the same delivery;
- authority is always the current one: a rule is checked again at each send, each claim, each result and each
  prompt run (still_valid), with its author's current authority, so a reporting-line or grant change makes a
  stale rule or claim start nothing. A check result is data: it never changes a rule or an authority;
- the persisted identity of each write (command_identity), so that a repeated tool call gets its first receipt;
- the texts and the input schemas of the agent tools.

The hub passes facts in, applies each returned plan with its own trigger functions inside one transaction, and maps
Refused to its ToolError. Standard library only.
"""
import hashlib
import json
import re
import shlex

CODE_MAX = 65536            # bytes of one saved check: the limit of a repository check (owner API 1.8)
RULES_MAX = 20              # active and paused rules that one agent saved itself (plan C12)
ACTIONS = ("pause", "resume", "delete", "check_now")
RULE_FIELDS = ("agent", "schedule", "task")      # the hub checks them (1.7); no late window and no cap (plan C12)
SAVE_KEYS = {"request_id", "trigger_id", "base_revision", "check", "task_id"} | set(RULE_FIELDS)
CHANGE_KEYS = {"request_id", "trigger_id", "base_revision", "action", "task_id"}    # call_tool adds task_id
CHECK_KEYS = {"code", "args", "timeout_seconds", "condition"}
LINE_FORM = "lines"         # plan P4: the `form` of a check that prints lines
SAVED = ("code", "sha256", "bytes")       # the fields of a stored saved check that come from its code
PROGRESS = re.compile(r"progress[ \t]+([-+]?(?:\d+(?:\.\d*)?|\.\d+))")    # AUTONOMY.md 6.5: a target's progress line
REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,63}")
OWNER, FLEET, SELF, NONE = 3, 2, 1, 0       # levels; OWNER is only the owner's own rules
OPS = {">": "more than", ">=": "at least", "<": "less than", "<=": "at most", "==": "equal to", "!=": "not equal to"}


class Refused(Exception):
    """A request that the caller may not make, or that is not valid. The hub answers it as a tool error."""


class Org:
    """What the module reads from the hub: the fleet manager's name, the team.json agents, the hub's one authority
    function, authority(actor, target, action) -> (allowed, reason), and the features
    that each helper reports. The module never decides authority itself: it asks this function, so the rules of the
    module and of the hub cannot drift apart."""

    def __init__(self, manager, agents, authority, features=None):
        self.manager, self.agents, self.authority = manager, agents, authority
        self.features = features or (lambda agent: ())     # hub.helper_features: what an agent's helper reports


def number_text(x):
    """A number as an agent and the owner read it: a whole one whole, another to 15 digits. With :g a check's
    10485760 read as 1.04858e+07 (28 October 2026)."""
    return f"{int(x)}" if float(x).is_integer() else f"{x:.15g}"


def team_authority(manager, agents):
    """A stand-in with the rules of hub.authority, for the tests of this module."""
    def authority(actor, target, action):
        if actor not in agents:
            return False, f"{actor} is not an agent of this team."
        if action == "rule":
            if target not in agents:
                return False, f"There is no agent {target} in the team."
            if actor in (manager, target):
                return True, None
            return False, f"Only {target} itself or {manager} sets {target}'s rules."
        up = (agents.get(target) or {}).get("reports_to") or manager
        if (agents.get(target) or {}).get("role") not in ("worker", "lead") or up != actor:
            return False, f"'{target}' does not report to you."
        if (agents.get(target) or {}).get("active", True) is False:
            return False, f"{target} is in setup. The owner activates it in Fleet."
        return True, None
    return authority


def level(org, caller, target):
    """The caller's level over `target`'s rules, from the one authority function: FLEET for the fleet manager, SELF
    for the target itself, NONE when not allowed."""
    if not org.authority(caller, target, "rule")[0]:
        return NONE
    return FLEET if caller == org.manager else SELF


def boss(org, name):
    """The agent that gives `name` its tasks in the reporting lines: its lead, or the fleet manager. None for the
    fleet manager. As hub.reports_to."""
    conf = org.agents.get(name) or {}
    if name == org.manager or conf.get("role") == "manager":
        return None
    up = conf.get("reports_to")
    return up if up in org.agents and up != name else org.manager


# ---------------------------------------------------------------- authority over rules

def creator_rank(org, rule):
    """The rank that a rule needs from its author: OWNER for the owner's rules, SELF for an agent's rule for itself,
    and FLEET for every other author, which is the fleet manager (and an older author that is neither, which only the
    fleet manager takes over). The author (created_by) is the agent that saved the rule last: an agent's accepted edit
    makes the editor the author, and the history keeps every author. An owner edit keeps the author."""
    by = rule.get("created_by") or "owner"
    return OWNER if by == "owner" else SELF if by == rule["agent"] and by != org.manager else FLEET


def may_read(org, caller, rule):
    """By current authority only: the fleet manager sees every rule, and an agent the rules that wake it. An agent
    that left the team, and an author that lost its authority, see nothing (the source and history can hold the
    team's own data)."""
    return caller == org.manager or level(org, caller, rule["agent"]) >= SELF


def may_control(org, caller, rule, action=None):
    """None, or Refused: may `caller` edit `rule`, or apply `action` to it? Agents never change the owner's rules. The
    fleet manager changes every agent's rule. Otherwise the caller needs, now, at least the rank that the rule needs
    from its author: so an agent changes its own rule for itself but not what the fleet manager set for it. Only the
    owner resumes a rule that the owner paused."""
    tid = rule["id"]
    if not may_read(org, caller, rule):
        raise Refused(f"Trigger {tid} is not yours.")
    need = creator_rank(org, rule)
    if need == OWNER:
        raise Refused(f"The owner set trigger {tid}. Only the owner changes it, in Fleet. Tell your requester what "
                      f"should change.")
    if caller != org.manager and level(org, caller, rule["agent"]) < max(SELF, need):
        raise Refused(f"{rule.get('created_by')} set trigger {tid}. You cannot change it.")
    if action == "resume":
        rank = pause_rank(org, rule)
        if rank == OWNER:
            raise Refused(f"The owner paused trigger {tid}. Only the owner resumes it.")
        if caller != org.manager and level(org, caller, rule["agent"]) < rank:
            raise Refused(f"{rule.get('paused_by')} paused trigger {tid}. Only the fleet manager resumes it.")


def pause_rank(org, rule):
    """The rank that a resume needs, from who paused the rule (paused_by), as creator_rank does for an edit: OWNER for
    the owner's pause (and for a paused rule without a pauser), SELF for the target's own pause, NONE for the hub's
    pause (anyone who may change the rule resumes it once still_valid passes), and FLEET for every other pauser. So
    an agent never resumes what the fleet manager paused."""
    by = rule.get("paused_by")
    if by == "hub":
        return NONE
    if by == "owner" or (by is None and rule.get("state") == "paused"):
        return OWNER
    if by is None:
        return NONE
    return SELF if by == rule["agent"] and by != org.manager else FLEET


def check_set(org, caller, target):
    """None, or Refused with the hub's own reason: may `caller` set a rule for `target`?"""
    if target not in org.agents:
        raise Refused(f"There is no agent {target} in the team.")
    allowed, why = org.authority(caller, target, "rule")
    if not allowed:
        raise Refused(why)


def wake_route(org, target):
    """(route, None), or (None, why) when a match cannot start anything that someone can follow. A wake-up of the
    fleet manager is one inbox message. Otherwise it is a task for the target, whose requester is the target's boss in
    the reporting lines:

    {"kind": "message", "to": <fleet manager>}
    {"kind": "task", "owner": <target>, "requester": <fleet manager>, "parent": None}
    {"kind": "task", "owner": <target>, "requester": <R>, "parent": {"owner": <R>, "requester": <fleet manager>}}

    A requester other than the fleet manager reads results only in its own task sessions, so the hub starts a parent
    task for it in the same transaction, and the target's task is its subtask. That requester must be a lead (it needs
    the team tools) that reports to the fleet manager. Every task of the route must pass the one authority function
    (action "task"), so a wake never starts a task that its requester could not give."""
    if target == org.manager:
        return {"kind": "message", "to": target}, None
    requester = boss(org, target)
    parent = None
    if requester != org.manager:
        conf = org.agents.get(requester) or {}
        if conf.get("role") != "lead":
            return None, (f"{requester} would receive {target}'s result, but it is not a lead, so it has no tools to "
                          f"check results. The owner can make it a lead.")
        if boss(org, requester) != org.manager:
            return None, (f"{requester} would receive {target}'s result, but it reports to {boss(org, requester)}, "
                          f"not to the manager. A wake-up can go through one lead only.")
        parent = {"owner": requester, "requester": org.manager}
        allowed, why = org.authority(org.manager, requester, "task")
        if not allowed:
            return None, why
    allowed, why = org.authority(requester, target, "task")
    if not allowed:
        return None, why
    return {"kind": "task", "owner": target, "requester": requester, "parent": parent}, None


# ---------------------------------------------------------------- saved code and where it runs (machine placement)

def flag(words, *names):
    """The value of a command-line option, "--sandbox x" or "--sandbox=x", or None."""
    for i, word in enumerate(words):
        for name in names:
            if word == name and i + 1 < len(words):
                return words[i + 1]
            if name.startswith("--") and word.startswith(name + "="):
                return word[len(name) + 1:]
    return None


def option_values(words, *names):
    """Every value of a repeatable option ("--allowedTools a b" stops at the next option, or "--allowedTools=a,b")."""
    out = []
    for i, word in enumerate(words):
        for name in names:
            if word == name:
                for value in words[i + 1:]:
                    if value.startswith("-"):
                        break
                    out += [v for v in value.replace(",", " ").split() if v]
            elif word.startswith(name + "="):
                out += [v for v in word[len(name) + 1:].replace(",", " ").split() if v]
    return out


def execution_grant(conf):
    """(granted, why): the narrow execution grant for saved code, one rule for every runtime. Saved code runs as the
    runner's machine user, outside every AI session, so it may run only where it adds no access: the runner's existing
    runtime grant (its start command and allow list in team.json) already runs any command without asking, and every
    restriction that this runtime still applies is applied to the check as well. There is no new grant, no inference
    from the reporting lines and no approval of each code version.

    - Codex: --sandbox danger-full-access with --ask-for-approval never, or its bypass flag, and no -c override of the
      sandbox or the approvals. No restriction is left, so it is granted.
    - Claude Code: --dangerously-skip-permissions, --permission-mode bypassPermissions, or Bash allowed without a
      pattern (the full-access worker form: dontAsk with Bash), and a start that keeps every built-in tool. Fleet's
      deny list of a worker (fleet.py DENY and PROTECTED) names files and command patterns, and a Bash that runs any
      command without asking already reaches past a pattern, so a check adds no access (plan C14, the owner's yes of
      26 October 2026). It runs on the agent's own machine, as its own user.
    - Everything else asks before commands, or is not known: not granted."""
    try:
        words = shlex.split(conf.get("start") or "")
    except ValueError:
        return False, "Its start command in team.json cannot be read."
    runtime = conf.get("runtime")
    if runtime == "codex":
        configs = option_values(words, "-c", "--config")
        if any(c.split("=", 1)[0].strip().startswith(("sandbox", "approval")) for c in configs):
            return False, "Its Codex start command changes the sandbox or the approvals with -c, which Fleet does not read."
        if "--dangerously-bypass-approvals-and-sandbox" in words or "--yolo" in words or (
                flag(words, "--sandbox", "-s") == "danger-full-access" and
                flag(words, "--ask-for-approval", "-a") == "never"):
            return True, "Codex already runs any command without asking, with no sandbox."
        return False, ("Its Codex runtime asks before commands or uses a sandbox. The grant needs --sandbox "
                       "danger-full-access and --ask-for-approval never.")
    if runtime == "claude":
        allow = list(conf.get("allow") or []) + option_values(words, "--allowedTools", "--allowed-tools")
        bypass = "--dangerously-skip-permissions" in words or flag(words, "--permission-mode") == "bypassPermissions"
        # The start must keep every built-in tool: one that removes a tool, such as Bash, would let a check run what
        # the session itself cannot.
        every_tool = flag(words, "--tools") in (None, "default") and \
            not option_values(words, "--disallowedTools", "--disallowed-tools")
        if not (bypass or any(a in ("Bash", "Bash(*)", "Bash(*:*)") for a in allow)):
            return False, (f"Its Claude Code runtime asks before commands (permission mode "
                           f"{flag(words, '--permission-mode') or 'default'}).")
        if not every_tool:
            return False, ("Its Claude Code start removes a built-in tool (--tools or --disallowedTools), so a check "
                           "could run what its sessions cannot.")
        return True, "Claude Code already runs any command without asking, with every built-in tool."
    return False, f"There is no known execution grant for the runtime {runtime}."


def runner_of(rule_or_target, check=None):
    """The agent whose helper runs a rule's check: always the rule's own agent (plan P4). A check runs only on its own
    agent's machine, with that agent's read keys; a stored check that names another machine in run_on (from before
    plan P4) does not run at all (still_valid)."""
    return rule_or_target["agent"] if isinstance(rule_or_target, dict) else rule_or_target


def runner_problem(org, agent):
    """Why `agent`'s own machine cannot run its saved checks, or None: it is not in the team, is in setup, or its
    runtime asks before commands (execution_grant), so a check would add a capability."""
    conf = org.agents.get(agent)
    if conf is None:
        return f"There is no agent {agent} in the team to run the check."
    if conf.get("active", True) is False:
        return f"{agent} is in setup and cannot run checks."
    granted, why = execution_grant(conf)
    if not granted:
        return (f"{agent} cannot run saved code: {why} A check runs only on its own agent's machine, and only where "
                f"that agent's sessions already run any command without asking.")
    return None


def code_grant(org, author, target):
    """(allowed, reason): may code that `author` saved run as `target`'s check? It runs on target's own machine, as
    target's user and with target's read keys (plan P4), so it must be target's own code -- a check adds no
    capability only then -- and target's runtime must already run any command without asking (execution_grant).
    Another agent's code never runs with target's keys, the fleet manager's included: it sets target a wake-up without
    a check, or asks target to write its check."""
    problem = runner_problem(org, target)
    if problem:
        return False, problem
    if author != target:
        return False, (f"A check runs only with code that its own agent saved, and {author} saved this one: only "
                       f"{target} saves the code of {target}'s checks. Set {target} a wake-up without a check, or "
                       f"ask {target} to write its check.")
    return True, None


def foreign_runner(check, target):
    """The other agent that a stored check names in run_on (from before plan P4), or None."""
    run_on = (check or {}).get("run_on")
    return run_on if run_on not in (None, target) else None


def saved_check(value, author, old=None):
    """(stored check, source): an agent's check, with its code kept by SHA-256. A stored version never changes: new
    code is a new SHA-256 and a new trigger revision. The fields say the form: with condition it is the value form
    (owner API 1.8), without it the line form (plan P4, "form": "lines"). In an edit, a check without
    "code" keeps the code of `old` (the stored check), so new args need no resend; source is then None. The caller
    becomes code_by, the agent that answers for the code. The hub checks args, timeout_seconds, condition and
    repeat_minutes with its own rules. An agent cannot pin a repository check: path and commit are not agent
    fields."""
    if not isinstance(value, dict):
        raise Refused("check must be an object: code, and optional args and timeout_seconds. Use null to remove the "
                      "check.")
    extra = sorted(set(value) - CHECK_KEYS)
    if extra:
        if extra[0] == "run_on":
            raise Refused("check has no field run_on: a check runs only on its own agent's machine.")
        if extra[0] == "repeat_minutes":
            raise Refused("check has no field repeat_minutes: a check wakes once for each new line, and a value "
                          "check once while its condition holds and again only after a quiet run.")
        raise Refused(f"check has no field {extra[0]}. Its fields are code, args and timeout_seconds (and condition "
                      f"in the value form).")
    rest = {k: v for k, v in value.items() if k != "code"}
    if "condition" in value:
        rest["repeat_minutes"] = None       # kept for the app that reads it; plan P4 took its meaning away
    else:
        rest["form"] = LINE_FORM
    if "code" not in value:
        if not old or old.get("code") != "saved":
            raise Refused("check.code is required: the text of the Python program that the check runs.")
        return dict(rest, **{k: old[k] for k in SAVED}, code_by=author), None
    code = value["code"]
    if not isinstance(code, str) or not code.strip():
        raise Refused("check.code must be the text of a Python program.")
    if "\x00" in code:
        raise Refused("check.code must not contain a NUL character.")
    try:
        data = code.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("check.code must be valid Unicode text.") from None
    if len(data) > CODE_MAX:
        raise Refused(f"check.code has {len(data)} bytes; the limit is {CODE_MAX} bytes (64 KiB).")
    return dict(rest, code="saved", sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), code_by=author), code


def still_valid(org, rule):
    """(True, None), or (False, why), with the current team and authority. The hub asks before each send of a check,
    at each claim, before each decision of a result and at each prompt run, so a rule or a claim that became stale
    starts nothing: the author lost its authority, the code's author may no longer set the target's rules, the
    target's runtime lost its grant, or the target went into setup. The run then ends without a task or a message,
    and the hub pauses the rule with the reason. The owner's own rules keep the hub's 1.7 and 1.8 rules."""
    target = rule["agent"]
    if target not in org.agents:
        return False, f"{target} is no longer in the team."
    if org.agents[target].get("active", True) is False:
        return False, f"{target} is in setup."
    by = rule.get("created_by") or "owner"
    if by == "owner":
        return True, None
    need = creator_rank(org, rule)
    if need != SELF and level(org, by, target) < need:
        return False, (f"{by} set this rule and no longer has authority over {target}. The fleet manager can save it "
                       f"again to take it over.")
    route, why = wake_route(org, target)
    if route is None:
        return False, why
    check = rule.get("check")
    if check and check.get("code") == "saved":
        other = foreign_runner(check, target)
        if other:
            return False, (f"This check was saved to run on {other}'s machine. A check runs only on its own agent's "
                           f"machine now: save the check again, without run_on.")
        allowed, why = code_grant(org, check.get("code_by"), target)
        if not allowed:
            return False, why
    return True, None


# ---------------------------------------------------------------- plans for the agent tools

def trigger_ref(value):
    """A trigger number from 7 or "7"."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    if isinstance(value, str) and value.strip().isdigit() and int(value) >= 1:
        return int(value)
    raise Refused("trigger_id must be a trigger number, for example 7.")


def revision_of(args):
    base = args.get("base_revision")
    if isinstance(base, bool) or not isinstance(base, int) or base < 1:
        raise Refused("base_revision is required: the revision that see_triggers shows for the trigger.")
    return base


def plan_save(org, caller, args, rule=None, rules=()):
    """The plan of one save_trigger call, or Refused. The hub then checks the 1.7 fields with trigger_fields and the
    1.8 check fields with trigger_check_spec, and applies the plan in one transaction, with a trigger_history row.

    rule: the stored rule of args["trigger_id"] for an edit, or None when there is no such trigger.
    rules: the stored rules that are not deleted, for RULES_MAX: the active and paused rules that the caller saved.

    Returns {"op": "create" or "edit", "trigger_id", "base_revision", "fields", "route", "source", "by"},
    and "check" when the save sets the check. fields has the 1.7 fields (an edit only the given ones). check is None
    (no check, or remove it) or the stored saved check; without the key, an edit keeps the stored check. source is
    the code text to keep by its SHA-256, or None when the code is not new. by becomes the rule's author
    (created_by), also in an edit. The hub first looks up command_identity(caller, "save_trigger", args).

    Saved code runs only on the target's own machine (code_grant): a save that would run it anywhere else, or on a
    machine whose runtime asks before commands, is refused. Nothing approves an exception."""
    if not isinstance(args, dict):
        raise Refused("save_trigger needs an object of fields.")
    extra = sorted(set(args) - SAVE_KEYS)
    if extra:
        raise Refused(f"save_trigger has no field {extra[0]}.")
    editing = args.get("trigger_id") is not None
    fields = {k: args[k] for k in RULE_FIELDS if k in args}
    if editing:
        tid = trigger_ref(args["trigger_id"])
        if rule is None or rule.get("id") != tid:
            raise Refused(f"There is no trigger {tid}.")
        base = revision_of(args)
        may_control(org, caller, rule)
        if not fields and "check" not in args:
            raise Refused("Give at least one of agent, schedule, task and check.")
        target = fields.get("agent", rule["agent"])
    else:
        if "base_revision" in args:
            raise Refused("base_revision belongs to a change of an existing trigger, with trigger_id.")
        missing = [k for k in ("schedule", "task") if k not in args]
        if missing:
            raise Refused(f"A new trigger needs {' and '.join(missing)}.")
        tid, base = None, None
        if fields.get("agent") is None:
            fields["agent"] = caller
        target = fields["agent"]
    if not isinstance(target, str) or not target:
        raise Refused("agent must be an agent name.")
    check_set(org, caller, target)
    if org.agents[target].get("active", True) is False:
        raise Refused(f"{target} is in setup. The owner activates it in Fleet.")
    route, why = wake_route(org, target)
    if route is None:
        raise Refused(why)
    task = fields.get("task", rule.get("task") if editing else None)
    if route["kind"] == "message" and isinstance(task, dict) and task.get("needs", "none") != "none":
        raise Refused("A wake-up of the manager is an inbox message, so task.needs must be none.")
    plan = {"op": "edit" if editing else "create", "trigger_id": tid, "base_revision": base,
            "fields": fields, "route": route, "source": None, "by": caller}
    old = rule.get("check") if editing else None
    if "check" in args or not editing:
        if args.get("check") is None:
            plan["check"] = None
        else:
            plan["check"], plan["source"] = saved_check(args["check"], caller, old)
    check = plan["check"] if "check" in plan else old
    moved = editing and target != rule["agent"]
    if check and check.get("code") == "saved" and ("check" in plan or moved):
        if foreign_runner(check, target):
            raise Refused(f"This check runs on {check['run_on']}'s machine (run_on), and a check runs only on its own "
                          f"agent's machine now. Give the check again, without run_on.")
        allowed, why = code_grant(org, check["code_by"], target)
        if not allowed:
            raise Refused(why)
        if "check" not in plan and ("approval" in check or "run_on" in check):     # what plan P4 took away goes
            plan["check"] = {k: v for k, v in check.items() if k not in ("approval", "run_on")}
    if not editing:
        have = sum(1 for r in rules if r.get("created_by") == caller and r.get("state") in ("active", "paused"))
        if have >= RULES_MAX:
            raise Refused(f"You have {have} active or paused wake-up rules of your own; the limit is {RULES_MAX}. "
                          f"Delete one that you no longer need first.")
    return plan


def plan_change(org, caller, args, rule):
    """The plan of one change_trigger call, or Refused: {"op": the action, "trigger_id", "base_revision", "by"}. The
    hub checks the trigger's state (TRIGGER_ACTIONS) and base_revision, and applies it as for the owner, with the
    caller's name as paused_by for a pause. check_now never starts a task."""
    if not isinstance(args, dict):
        raise Refused("change_trigger needs an object of fields.")
    extra = sorted(set(args) - CHANGE_KEYS)
    if extra:
        raise Refused(f"change_trigger has no field {extra[0]}.")
    tid = trigger_ref(args.get("trigger_id"))
    if rule is None or rule.get("id") != tid:
        raise Refused(f"There is no trigger {tid}.")
    action = args.get("action")
    if action not in ACTIONS:
        raise Refused("action must be pause, resume, delete or check_now.")
    base = revision_of(args)
    may_control(org, caller, rule, action)
    if action == "check_now" and not rule.get("check"):
        raise Refused(f"Trigger {tid} has no check. Add one with save_trigger, or wait for its time.")
    if action in ("resume", "check_now"):
        valid, why = still_valid(org, rule)
        if not valid:
            raise Refused(why)
    return {"op": action, "trigger_id": tid, "base_revision": base, "by": caller}


def command_identity(caller, tool, args):
    """(request_id, digest): the persisted identity of one write by an agent tool. The hub keeps (caller, request_id,
    tool, digest, receipt) in the same transaction as the write. An exact repeat (the same caller, request_id, tool
    and digest) gets the stored receipt again and changes nothing, also after the rule is done or deleted and after a
    restart. The same request_id with another tool or other fields is refused. A refused command stores nothing, so
    its request_id can be used again. The digest covers every field except request_id and task_id."""
    rid = args.get("request_id") if isinstance(args, dict) else None
    if not isinstance(rid, str) or not REQUEST.fullmatch(rid):
        raise Refused("request_id is required: a new text of 8 to 64 letters, digits, '.', '_', ':' or '-' for each "
                      "change, for example a UUID. Send the same request_id again only to repeat the same change.")
    body = {k: v for k, v in args.items() if k not in ("request_id", "task_id")}
    digest = hashlib.sha256(json.dumps([tool, body], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                       default=str).encode("utf-8")).hexdigest()
    return rid, digest


def same_command(stored, tool, digest):
    """None for an exact repeat of a stored command ({"tool", "digest", "receipt"}), else Refused."""
    if stored["tool"] != tool or stored["digest"] != digest:
        raise Refused("This request_id was already used for another change. Use a new request_id.")


def receipt(op, trigger_id, revision, run_id=None):
    """What the hub stores for one accepted write, and gives again for an exact repeat."""
    return {"op": op, "trigger_id": trigger_id, "revision": revision, "run_id": run_id}


def receipt_text(r, replayed=False):
    verb = {"create": "Created", "edit": "Changed", "pause": "Paused", "resume": "Resumed", "delete": "Deleted",
            "check_now": "Sent the check of"}[r["op"]]
    text = f"{verb} trigger {r['trigger_id']} (revision {r['revision']})."
    if r.get("run_id"):
        text += f" Run {r['run_id']}: read its result with see_triggers in a minute."
    if replayed:
        text += " This repeats an earlier request with the same request_id, so nothing new was done."
    return text


def history_detail(action, old, new):
    """The detail of one trigger_history row. An edit gives each changed field before and after; a saved check
    appears with its SHA-256, author and runner, never with its text. Another action gives the state before and
    after."""
    keys = RULE_FIELDS + ("check", "created_by")
    if action == "create":
        return {"created": {k: new.get(k) for k in keys}}
    if action == "edit":
        return {"changed": {k: {"before": old.get(k), "after": new.get(k)} for k in keys if old.get(k) != new.get(k)}}
    return {"state": {"before": old.get("state"), "after": new.get("state")}}


# ---------------------------------------------------------------- what a wake-up starts

def manager_decision(last):
    """(state, reason) of one prompt run whose route is a message to the fleet manager: "started" writes that message
    in the run's transaction, unless the rule's last message is still unread. last: what the newest started run
    started, None or {"ref", "open", "ended", "ended_at"}. A check run of an agent's rule wakes through its lines
    (AUTONOMY.md 6.5: lines_decision), not here. No count of wake-ups caps a rule (plan C12)."""
    if last and last["open"]:
        return "not_started", f"{last['ref']} is still unread."
    return "started", None


def manager_message(trigger_id, fields, line):
    """The inbox message of a fleet-manager wake-up. It starts with [hub], as every hub message does, and ends with
    the provenance line of hub.trigger_provenance (which, for a check, says what the check found)."""
    parts = [f"[hub] Wake-up from trigger {trigger_id}: {fields['title']}"]
    if fields.get("details"):
        parts.append(fields["details"])
    parts += [f"Done when: {fields['done_when']}", line]
    return "\n".join(parts)


def batch_fields(lead):
    """The task fields of a lead's one open task for its team's waiting results (plan P9.11). A wake-up, a case, a
    duty review or the work from a conversation (hub.conversation_line_task) of an agent under the lead is a
    subtask of it, so their results arrive in one session of the lead, which checks them together. The hub starts
    a new one when the lead has delivered the last."""
    return {"owner": lead, "title": "Your team's wake-up and case results",
            "details": ("The wake-ups, duty cases and duty reviews of the agents that you lead, and the work that "
                        "they open from conversations, are subtasks of this task, and more join it while it is "
                        "open. Their results, questions and permission prompts arrive in this session. Check each "
                        "result with check_result: closely where an agent's record is weak, by sample where it is "
                        "good; you decide. Answer with answer. Deliver this task when no subtask is open."),
            "done_when": "Every subtask has ended and you have checked its result.", "needs": "none"}


# ---------------------------------------------------------------- the lines of a check (AUTONOMY.md 6.5)

def value_line(trigger_id):
    """The one line that a value check's result reads as while its value matches its condition (plan P4): it begins
    with the rule's own id and stays the same while the condition holds, so it wakes once, and again only after a
    quiet run, through the line delivery. The value and the summary go into the wake's text beside it."""
    return f"trigger {trigger_id}: its check's value matches its condition"


def progress_of(lines):
    """(progress or None, the other lines): a first line "progress <number>" is the progress of a target that names
    the check (AUTONOMY.md 6.5), and never a wake line."""
    found = PROGRESS.fullmatch(lines[0]) if lines else None
    if not found:
        return None, list(lines)
    return float(found.group(1)), list(lines[1:])


def new_lines(printed, accepted):
    """The lines of a run that the last accepted run did not print, each once, in the run's order: the only lines
    that wake the agent. So a line is never told twice, and one that the hub could not deliver yet is still new at
    the next run, because only a run whose lines were delivered is accepted."""
    seen, out = set(accepted or ()), []
    for line in printed:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def lines_decision(new, check_now, wake_open, held):
    """(state, reason) of one run of a line check: "quiet" when no line is new; "not_started" for Check now, which
    never wakes; "joined" when the check's wake is still open, and the new lines go into it as a message (one open
    wake for each check); "waiting" with the one reason that holds the lines, such as a usage limit, and they wait with
    their run; else "started", one new wake with the new lines."""
    if not new:
        return "quiet", None
    if check_now:
        return "not_started", "Check now never starts a wake-up."
    if wake_open:
        return "joined", None
    if held:
        return "waiting", held
    return "started", None


def lines_text(lines):
    """Lines of a check as they go into a text that an agent reads: one JSON array, so a quote or a bracket in a line
    cannot end it, and a reader sees where each line begins and ends."""
    return json.dumps(list(lines), ensure_ascii=False)


def split_lines(lines, budget):
    """(the first lines whose JSON fits in `budget` characters, the rest): a wake text keeps its size, and the rest
    goes into a message of the same wake, so no line is dropped."""
    head = []
    for line in lines:
        if head and len(lines_text(head + [line])) > budget:
            break
        head.append(line)
    return head, list(lines[len(head):])


# ---------------------------------------------------------------- tool texts

def schedule_text(s):
    if s["kind"] == "every":
        return f"every {s['minutes']} minutes"
    if s["kind"] == "once":
        return f"once, at {s['at'].replace('T', ' ')} {s['timezone']}"
    if s["kind"] == "daily":
        days = "every day" if not s.get("days") else ", ".join(s["days"])
        return f"{days} at {s['time']} {s['timezone']}"
    return f"day {s['day']} of each month at {s['time']} {s['timezone']} (a month without that day is skipped)"


def is_lines(check):
    """True for a check of the line form (plan P4)."""
    return isinstance(check, dict) and check.get("form") == LINE_FORM


def check_known(check):
    """True when this release reads a stored check (plan P0): the value form, which has no `form` and has the
    condition and the repeat rule that the hub decides a value with, or the line form of plan P4 (saved code with
    "form": "lines"). A check of any other form reads as quiet: the hub opens no run of it and starts nothing from
    it."""
    if not isinstance(check, dict):
        return False
    if "form" in check:
        return is_lines(check) and check.get("code") == "saved"
    if "repeat_minutes" not in check:
        return False
    cond = check.get("condition")
    if not isinstance(cond, dict) or cond.get("op") not in OPS:
        return False
    value = cond.get("value")
    return isinstance(value, (int, float)) and not isinstance(value, bool) and abs(value) < float("inf")


def check_text(c, target):
    if not c:
        return "none: the task starts at each time"
    if not check_known(c):
        return "a check of a newer form, which this release does not run: it reads as quiet"
    if c.get("code") == "saved":
        code = f"saved code {c['sha256'][:12]} ({c['bytes']} bytes, by {c['code_by']}), on {target}'s own machine"
    else:
        code = f"{c['path']} at {c['commit'][:7]}, pinned by the owner"
    if is_lines(c):
        return f"{code}; each line that it prints and its last run did not print wakes {target}"
    cond = c["condition"]
    if c.get("code") == "saved":        # an agent's value check reads as one line (plan P4)
        return (f"{code}; it wakes {target} once when the value is {OPS[cond['op']]} {number_text(cond['value'])}, and again "
                f"only after a quiet run")
    repeat = ("once, until a check is quiet again" if c["repeat_minutes"] is None else
              f"again {c['repeat_minutes']} minutes after the last wake-up completed, while the check still matches")
    return f"{code}; it starts the wake-up when the value is {OPS[cond['op']]} {number_text(cond['value'])}; {repeat}"


def run_text(r, when):
    out = f"run {r['id']} for {when(r['due'])}: {r['state']}"
    if r.get("state") == "sent" and r.get("sent"):
        out += f", in flight since {when(r['sent'])}"
    if r.get("value") is not None:
        out += f", value {number_text(r['value'])}" + (f" ({lines_text([r['summary']])})" if r.get("summary") else "")
    if r.get("lines") is not None:
        n = len(r["lines"])
        out += f", printed {n} line{'' if n == 1 else 's'}"
    if r.get("error"):
        out += f", error {r['error']}" + (f" ({r['detail']})" if r.get("detail") else "")
    if r.get("task"):
        out += f", T-{r['task']}"
    if r.get("event_id"):
        out += f", M-{r['event_id']}"
    return out + (f". {r['reason']}" if r.get("reason") else ".")


def describe(rule, when):
    """One rule as lines for an agent. when(ts) gives a time in the rule's time zone (hub.trigger_when)."""
    state = rule["state"]
    if state == "paused":
        state = f"paused by {rule.get('paused_by') or 'the owner'}" + (
            f": {rule['paused_reason']}" if rule.get("paused_reason") else "")
    task = rule["task"]
    lines = [f"Trigger {rule['id']} (revision {rule['revision']}), set by "
             f"{rule.get('created_by') or 'owner'}, wakes {rule['agent']}: {state}.",
             f"  Schedule: {schedule_text(rule['schedule'])}." +
             (f" Next: {when(rule['next_due'])}." if rule.get("next_due") else ""),
             f"  Task: {task['title']} (needs {task['needs']}). Done when: {task['done_when']}",
             f"  Check: {check_text(rule.get('check'), rule['agent'])}."]
    armed = rule.get("armed")
    if armed and not armed.get("armed"):
        lines.append(f"  Armed: no. {armed.get('reason') or ''}".rstrip())
    if rule.get("failures"):        # plan C12: nothing pauses a failing check; this says that it is broken
        since = rule.get("failing_since")
        lines.append(f"  Failing" + (f" since {when(since)}" if since else "") + f": {rule['failures']} check "
                     f"error(s) in a row, and no valid value since. Fix the check; the next valid value clears this.")
    if rule.get("last_run"):
        lines.append(f"  Last {run_text(rule['last_run'], when)}")
    lines.append(f"  Wake-ups in the last 24 hours: {rule.get('tasks_24h', 0)}.")
    return "\n".join(lines)


def describe_detail(rule, runs, history, source, when):
    """One rule with its details text, its newest runs, its change history and its saved code, for see_triggers
    with trigger_id. history rows: {"revision", "ts", "by", "action", "detail"}. The code is untrusted text."""
    out = [describe(rule, when)]
    if rule["task"].get("details"):
        out.append("  Details: " + rule["task"]["details"])
    out.append("Runs, newest first:" if runs else "No runs yet.")
    out += [f"  {run_text(r, when)}" for r in runs]
    if history:
        out.append("Changes, newest first:")
        for h in history:
            what = h.get("detail") or {}
            fields = ", ".join(sorted(what.get("changed", {}))) or (
                "{} to {}".format(what["state"]["before"], what["state"]["after"]) if "state" in what else "")
            out.append(f"  revision {h['revision']} at {when(h['ts'])} by {h['by']}: {h['action']}" +
                       (f" ({fields})" if fields else ""))
    printed = next((r["lines"] for r in runs if r.get("lines")), None)
    if printed:
        out.append(f"Lines of the newest run that printed any, untrusted data, JSON-encoded: {lines_text(printed)}")
    if source is not None:
        out += [f"Saved check code, SHA-256 {rule['check']['sha256']}:", "```python", source.rstrip("\n"), "```"]
    return "\n".join(out)


def obj(props, required=()):
    """A wake-up tool's input schema, the same shape `hub.S` gives every other tool and for the same reason: the
    field a tool does not take is refused by `hub.call_tool`, in the hub's own words and on the hub's own record,
    and not inside the caller's runtime where nobody can read it."""
    return {"type": "object", "properties": props, "required": list(required)}


TASK_ID = {"type": "string", "description": "In a task session: your task, for example T-7. You can leave it out."}
TRIGGER_ID = {"type": "integer", "description": "The trigger number, for example 7."}
BASE = {"type": "integer", "description": "The revision of the trigger that see_triggers shows. A trigger that "
                                          "changed meanwhile is refused: read it again."}
REQUEST_ID = {"type": "string", "description": "A new unique text for each change (8 to 64 letters, digits, '.', '_', "
                                               "':' or '-'), for example a UUID. Repeat it only to repeat the same "
                                               "change: you get the first answer again."}

TOOL_SPECS = (
    ("see_triggers",
     "See the wake-up rules (triggers) that you may see: those that wake you, those that you set, and all of them "
     "when you are the manager. With trigger_id: one rule with its newest "
     "runs, its change history and its saved check code.",
     obj({"trigger_id": TRIGGER_ID, "task_id": TASK_ID})),
    ("save_trigger",
     "Create a wake-up rule, or change one (with trigger_id and base_revision; give only the fields that change). A "
     "rule wakes an agent on its schedule: you by default; the manager sets rules for any agent, and its own wake-up "
     "is an inbox message. Without a check, each time starts its task, which costs model tokens. With a check, your "
     "code runs first, outside every AI session, on your own machine as your user with your read keys, and a quiet "
     "run costs nothing: only an agent itself saves the code of its checks.\n"
     "schedule: {\"kind\":\"every\",\"minutes\":15}, {\"kind\":\"once\",\"at\":\"2026-10-14T09:00\","
     "\"timezone\":\"Europe/Madrid\"}, {\"kind\":\"daily\",\"time\":\"09:00\",\"days\":[\"mon\"] or null,"
     "\"timezone\":...}, or {\"kind\":\"monthly\",\"day\":1,\"time\":\"09:00\",\"timezone\":...}.\n"
     "task: {\"title\", \"details\", \"done_when\", \"needs\": \"none\", \"browser\" or \"screen\", \"goal_id\": a "
     "goal number or null}.\n"
     "check: {\"code\": a Python 3 program, \"args\": an optional JSON object of at most 4 KiB, "
     "\"timeout_seconds\": optional}. The program prints one line for each item that needs the agent now, beginning "
     "with the item's own id. Only lines that its last run did not print wake the agent: as a new task, or as a "
     "message to the check's open wake. Nothing printed wakes nobody. A check that a target names may print "
     "\"progress <number>\" as its first line. When the source cannot be read, end with an error: the third failed "
     "run in a row wakes the agent with the end of its error output. The program gets one argument, the JSON "
     "{\"trigger\", \"run\", \"args\"}, and runs with "
     "python3 -I in an empty folder. Never put a secret in the code or the args. In a change, a check without code "
     "keeps the saved code, and \"check\": null removes it. Your machine runs the code only from its own store, "
     "never from the hub: also write the program, byte for byte, to ~/fleet-checks/<its SHA-256>.py on your "
     "machine; the answer names that file.",
     obj({"request_id": REQUEST_ID, "trigger_id": TRIGGER_ID, "base_revision": BASE,
          "agent": {"type": "string", "description": "The agent that the rule wakes. Default: you."},
          "schedule": {"type": "object", "description": "When the rule runs. See the forms above."},
          "task": {"type": "object", "description": "What the agent does when the rule wakes it."},
          "check": {"description": "The check object above, or null for no check."},
          "task_id": TASK_ID}, ["request_id"])),
    ("change_trigger",
     "Pause, resume or delete a wake-up rule that you may change, or run its check once now (check_now never starts "
     "a wake-up; read its result later with see_triggers). Only the owner resumes a rule that the owner paused.",
     obj({"request_id": REQUEST_ID, "trigger_id": TRIGGER_ID, "base_revision": BASE,
          "action": {"type": "string", "enum": list(ACTIONS)}, "task_id": TASK_ID},
         ["request_id", "trigger_id", "base_revision", "action"])),
)
