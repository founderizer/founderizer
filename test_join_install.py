"""The join script (join.sh): the steps it takes on a Linux server and on a Mac, one OS user for each agent of that
machine, and `verify` as its last step.

Nothing here reaches a machine and nothing here joins a fleet. A step is measured in one of two ways: the function's
own text is run with stubs of its own (`run_step`), so the branch is really taken, or the script is read. The hub's
own serving of this script is in test_servers.py, and the per-agent user step itself is in test_hub_install.py,
because `hubsetup.py agent-users` is the one place that makes the user.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import lifecycle
from test_hub_install import run_shell, shell_function

KIT = Path(__file__).resolve().parent
SCRIPT = KIT / "join.sh"
TEXT = SCRIPT.read_text()
# The Linux path, in the order the script takes it. The firewall and the security updates come before the per-agent
# users and verify, because verify reads the firewall and says whether this machine is healthy as it now stands.
LINUX = ["reach", "checkout ", "server.py\" join", "updates", "firewall ", "harden ", "current ", "agent_users ",
         "verify_step "]


def run_step(name, call, stubs):
    """One function of join.sh with stubs of its own: (exit code, output)."""
    return run_shell(shell_function(SCRIPT, name) + "\n" + call + "\n", extra=stubs)


class Shape(unittest.TestCase):
    def test_the_script_is_valid_shell(self):
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True, capture_output=True)

    def test_the_linux_path_takes_its_steps_in_order(self):
        body = shell_function(SCRIPT, "linux")
        at = []
        for step in LINUX:
            self.assertIn(step, body, f"the Linux join has no step {step.strip()}")
            at.append(body.index(step))
        self.assertEqual(at, sorted(at), "the steps are not in the order the join takes them")

    def test_the_join_code_never_stands_in_an_argument(self):
        """The one-time code goes to server.py on standard input, and the script drops it from its environment."""
        self.assertIn("unset FLEET_JOIN", TEXT)
        for line in TEXT.splitlines():
            if "server.py\" join" in line:
                self.assertIn("printf '%s\\n' \"$code\" |", line)
                self.assertNotIn("--code", line)
        self.assertNotIn("$code\" --", TEXT)

    def test_a_machine_checkout_starts_on_the_configuration_ref(self):
        """The hub writes the owner's team.json on that ref, and the join itself put this machine in it, so verify
        reads the fleet as it now is. A hub from before the split has no such ref and keeps the old clone."""
        body = shell_function(SCRIPT, "checkout")
        self.assertIn('git clone -q -b config "$REPO" "$1"', body)
        self.assertIn('|| "$2" git clone -q "$REPO" "$1"', body)
        self.assertIn('take "$1" "$2"', shell_function(SCRIPT, "current"))
        self.assertIn('lifecycle.py" may-take "$1"', shell_function(SCRIPT, "take"))      # DevOps plan 0.1

    def test_the_whole_script_is_read_before_anything_runs(self):
        """A command that reads standard input would otherwise take the rest of the script."""
        self.assertTrue(TEXT.rstrip().endswith("main"))


class AgentUsers(unittest.TestCase):
    """One OS user for each agent of this machine, through the one command that makes it."""

    STUBS = ('as_worker() { printf "%s\\n" "$MACHINE_NAME"; }\n'
             'python3() { printf "python3 %s\\n" "$*" >> "$RAN"; }\n')

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-join-step-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.ran = self.tmp / "ran"

    def step(self, name):
        return run_step("agent_users", 'agent_users /kit\n',
                        f'MACHINE_NAME={name}\nRAN={self.ran}\n' + self.STUBS)

    def test_it_makes_a_user_for_each_agent_of_the_machine_the_hub_named(self):
        code, out = self.step("box")
        self.assertEqual(code, 0, out)
        self.assertIn("python3 /kit/hubsetup.py agent-users --team /kit/team.json --machine box",
                      self.ran.read_text())

    def test_a_machine_without_a_name_from_the_hub_makes_no_user(self):
        code, out = self.step("")
        self.assertEqual(code, 0, out)
        self.assertIn("no agent user is made", out)
        self.assertFalse(self.ran.exists(), "it called the command although the hub has not named this machine")

    def test_a_mac_keeps_one_user_for_its_agents(self):
        """A Mac agent's service is a LaunchAgent of a desktop session, so a second user would have to be logged in
        at the screen (PRODUCT.md P2)."""
        body = shell_function(SCRIPT, "mac")
        self.assertNotIn("agent_users", body)
        self.assertNotIn("useradd", body)
        self.assertIn("PRODUCT.md P2", body)

    def test_the_linux_path_asks_for_the_users_before_it_says_it_is_done(self):
        body = shell_function(SCRIPT, "linux")
        self.assertLess(body.index("agent_users "), body.index('say "done.'))


class Firewall(unittest.TestCase):
    """The join's firewall step is `hubsetup.py firewall` of the new checkout (test_hub_install.Firewall): incoming
    traffic over the private network only, SSH included, and no public SSH rule."""

    def test_it_takes_the_one_firewall_command_of_the_checkout(self):
        tmp = Path(tempfile.mkdtemp(prefix="fleet-join-firewall-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        ran = tmp / "ran"
        code, out = run_step("firewall", "firewall /home/fleet/fleet-server\n",
                             f'RAN={ran}\npython3() {{ printf "python3 %s\\n" "$*" >> "$RAN"; }}\n')
        self.assertEqual(code, 0, out)
        self.assertEqual(ran.read_text(), "python3 /home/fleet/fleet-server/hubsetup.py firewall\n")

    def test_a_firewall_that_could_not_be_set_stops_the_join(self):
        code, out = run_step("firewall", "firewall /kit\necho after\n", "python3() { return 1; }\n")
        self.assertEqual(code, 1)
        self.assertIn("could not be set", out)
        self.assertNotIn("after", out)


class Hardening(unittest.TestCase):
    """The join's step after its firewall is `hubsetup.py harden` of the new checkout (test_hub_install.Harden): SSH
    keys only, npm's seven days and Tailscale's own updates. It never stops the join: the server's own reading tells
    the hub what holds."""

    def test_it_takes_the_one_hardening_command_of_the_checkout_for_the_service_user(self):
        tmp = Path(tempfile.mkdtemp(prefix="fleet-join-harden-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        ran = tmp / "ran"
        code, out = run_step("harden", "harden /home/fleet/fleet-server\n",
                             f'RAN={ran}\npython3() {{ printf "python3 %s\\n" "$*" >> "$RAN"; }}\n')
        self.assertEqual(code, 0, out)
        self.assertEqual(ran.read_text(), "python3 /home/fleet/fleet-server/hubsetup.py harden --user fleet\n")

    def test_a_hardening_that_did_not_finish_is_said_and_the_join_goes_on(self):
        code, out = run_step("harden", "harden /kit\necho after\n", "python3() { return 1; }\n")
        self.assertEqual(code, 0, out)
        self.assertIn("the hardening of this server did not finish", out)
        self.assertIn("after", out)


class Updates(unittest.TestCase):
    """The first security updates run as apt's own daily services, so apt records the run as its timers do: a bare
    unattended-upgrade installs the same updates and leaves no upgrade-stamp until the first daily run, and the
    server's reading then gives the hub no time of a good update. The join waits for the services' own end and reads
    their results: a systemctl start that waits loses its connection when an update of libc6 or systemd re-executes
    systemd, and ends with an error while the services go on to a good end; and while systemd re-executes, it answers
    no question ("Failed to connect to system scope bus via local transport: Connection refused"). Both seen on
    Debian 13 on 5 November 2026."""

    START = "start --no-block apt-daily.service apt-daily-upgrade.service"
    POLL = "list-jobs --no-legend apt-daily.service apt-daily-upgrade.service"
    RESULTS = ["show -p Result --value apt-daily.service", "show -p Result --value apt-daily-upgrade.service"]

    def daily(self, polls=(), start=0, daily="success", upgrade="success"):
        """apt_daily with a stand-in systemctl that gives the polls their answers in order ("job": a job of the two
        services is listed, "unanswered": systemd answers nothing) and no job after them, and the result of each
        service: (what apt_daily said, the systemctl and sleep calls in their order)."""
        tmp = Path(tempfile.mkdtemp(prefix="fleet-join-apt-"))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        ran = tmp / "ran"
        stubs = (f'RAN="{ran}"\nPOLLS="{" ".join(polls)}"\n'
                 'systemctl() { printf "%s\\n" "$*" >> "$RAN"\n'
                 '    case "$*" in\n'
                 f'        "start "*) return {start} ;;\n'
                 '        "list-jobs "*) n=$(grep -c "^list-jobs" "$RAN"); set -- $POLLS\n'
                 '            [ "$n" -le $# ] || return 0\n'
                 '            eval "answer=\\${$n}"\n'
                 '            [ "$answer" = job ] || return 1\n'
                 '            echo "71 apt-daily-upgrade.service start running" ;;\n'
                 f'        "{self.RESULTS[0]}") echo {daily} ;;\n'
                 f'        "{self.RESULTS[1]}") echo {upgrade} ;;\n'
                 '    esac\n'
                 '}\n'
                 'sleep() { printf "sleep %s\\n" "$*" >> "$RAN"; }\n')
        code, out = run_step("apt_daily", 'if apt_daily; then echo "ended well"; else echo "did not end well"; fi',
                             stubs)
        self.assertEqual(code, 0, out)
        return out.strip().splitlines()[-1], ran.read_text().splitlines()

    def test_the_pending_updates_go_through_apts_own_two_services(self):
        body = shell_function(SCRIPT, "updates")
        self.assertIn("systemctl " + self.START, shell_function(SCRIPT, "apt_daily"))
        self.assertIn('apt_daily || say "some security updates did not install now; the daily run tries again"', body)
        self.assertNotRegex(body, r"(?m)^\s*unattended-upgrade ", "a bare unattended-upgrade records no run")
        self.assertLess(body.index("Automatic-Reboot"), body.index("apt_daily ||"),
                        "a server that restarts by itself after updates takes them in its daily run")

    def test_the_join_waits_while_the_jobs_are_listed_and_then_reads_each_result(self):
        said, calls = self.daily(["job", "job"])
        self.assertEqual(said, "ended well")
        self.assertEqual(calls, [self.START, self.POLL, "sleep 5", self.POLL, "sleep 5", self.POLL] + self.RESULTS)

    def test_a_question_that_systemd_does_not_answer_is_asked_again(self):
        said, calls = self.daily(["job", "unanswered", "job"])
        self.assertEqual(said, "ended well")
        self.assertEqual(calls.count(self.POLL), 4)
        self.assertEqual(calls[-2:], self.RESULTS)

    def test_only_12_unanswered_questions_in_a_row_end_the_wait(self):
        self.assertEqual(self.daily(["unanswered"] * 11)[0], "ended well")
        self.assertEqual(self.daily(["unanswered"] * 6 + ["job"] + ["unanswered"] * 6)[0], "ended well",
                         "an answer starts the count again")
        said, calls = self.daily(["unanswered"] * 12)
        self.assertEqual(said, "did not end well")
        self.assertEqual(calls.count(self.POLL), 12)
        self.assertNotIn(self.RESULTS[0], calls)

    def test_a_service_that_failed_is_said(self):
        self.assertEqual(self.daily(upgrade="exit-code")[0], "did not end well")
        # apt-daily-upgrade needs apt-daily: when apt-daily fails, the upgrade never runs and keeps its last result
        self.assertEqual(self.daily(daily="exit-code")[0], "did not end well")

    def test_a_start_that_systemd_refuses_is_said_at_once(self):
        """A masked or missing service: nothing runs, so there is nothing to wait for."""
        self.assertEqual(self.daily(start=1), ("did not end well", [self.START]))


class PatchPolicy(unittest.TestCase):
    """FLEET_REBOOT_TIME=<HH:MM> on the line gives an Ubuntu server the fleet patch policy as the last part of its
    update step: the DevOps repository's scripts/security/apt/52fleet-unattended-upgrades, byte for byte, with this
    server's own time, so it takes Ubuntu's -updates as well as -security and restarts at that time (UTC) when an
    update needs one. Without the time the join is as before: security updates only, and never a restart."""

    # The SHA-256 of that file of the DevOps repository (devops 082c792c), with @REBOOT_TIME@ still in it. The two are
    # copies: a change of one is a change of the other.
    TEMPLATE_SHA256 = "0e1a1635227d5249955ae33feba6d2d61889c5e4bcc36f2684caa6bc3623f178"
    TARGET = "/etc/apt/apt.conf.d/52fleet-unattended-upgrades"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-join-policy-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.file = self.tmp / "52fleet-unattended-upgrades"
        self.ran = self.tmp / "ran"

    def template(self):
        body = shell_function(SCRIPT, "patch_policy").splitlines()
        start = next(i for i, line in enumerate(body) if line.endswith("<<'EOF' || return 1"))
        return "\n".join(body[start + 1:body.index("EOF", start)]) + "\n"

    def tool(self, name, body):
        """A stand-in program in the test's own folder, first in PATH: a shell function cannot be named apt-get."""
        folder = self.tmp / "bin"
        folder.mkdir(exist_ok=True)
        (folder / name).write_text("#!/bin/sh\n" + body)
        (folder / name).chmod(0o755)
        return f'PATH="{folder}:$PATH"\n'

    def policy(self, reboot="true", at="02:18", target=None):
        """patch_policy with its file in a folder of the test's own, and an apt-config that reads the restart back as
        the arguments say: (exit code, output)."""
        text = shell_function(SCRIPT, "patch_policy").replace("> " + self.TARGET, f"> {target or self.file}")
        stubs = "REBOOT_TIME=02:18\n" + self.tool("apt-config", f"echo \"AUTO_REBOOT='{reboot}'\"\necho \"AT='{at}'\"\n")
        return run_shell(text + 'patch_policy || echo "the policy was not written"\n', extra=stubs)

    def updates(self, time, rebooting="false", policy_fails=False):
        """updates with stand-ins for apt, systemd and the policy: (exit code, output, the steps in their order)."""
        text = shell_function(SCRIPT, "updates").replace("/etc/apt/apt.conf.d/20auto-upgrades",
                                                         str(self.tmp / "20auto-upgrades"))
        stubs = (f'REBOOT_TIME="{time}"\nRAN="{self.ran}"\nAPT_LOCK_WAIT=1\n'
                 + self.tool("apt-config", f"echo \"AUTO_REBOOT='{rebooting}'\"\n")
                 + self.tool("apt-get", f'echo apt-get >> "{self.ran}"\n')
                 + 'systemctl() { :; }\n'
                 'apt_daily() { echo apt_daily >> "$RAN"; }\n'
                 'patch_policy() { echo "patch_policy $REBOOT_TIME" >> "$RAN"; return %d; }\n' % policy_fails)
        code, out = run_shell(text + "updates\necho after\n", extra=stubs)
        return code, out, self.ran.read_text().splitlines() if self.ran.exists() else []

    def check(self, time, os_id="ubuntu"):
        """The check of FLEET_REBOOT_TIME at the start of the Linux join: (exit code, output)."""
        body = shell_function(SCRIPT, "linux").splitlines()
        start = body.index('    case "$REBOOT_TIME" in')
        fragment = "\n".join(body[start:body.index("    esac", start) + 1])
        return run_shell(fragment + "\necho accepted\n", extra=f'REBOOT_TIME="{time}"\nID={os_id}\n')

    def test_the_template_is_the_devops_file_byte_for_byte(self):
        self.assertEqual(hashlib.sha256(self.template().encode()).hexdigest(), self.TEMPLATE_SHA256)

    def test_it_writes_the_template_with_this_servers_time_and_says_what_apt_reads(self):
        code, out = self.policy()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.file.read_text(), self.template().replace("@REBOOT_TIME@", "02:18"))
        self.assertIn('        "${distro_id}:${distro_codename}-updates";\n', self.file.read_text())
        self.assertIn('Unattended-Upgrade::Automatic-Reboot-Time "02:18";\n', self.file.read_text())
        self.assertIn("a restart at 02:18 UTC when an update needs one", out)

    def test_an_apt_file_that_changes_the_restart_is_said(self):
        for reboot, at in (("false", "02:18"), ("true", "now")):
            code, out = self.policy(reboot, at)
            self.assertEqual(code, 0, out)
            self.assertIn("apt-config shows no restart at 02:18", out)

    def test_a_file_that_cannot_be_written_is_a_failure(self):
        code, out = self.policy(target=self.tmp / "missing" / "52fleet-unattended-upgrades")
        self.assertEqual(code, 0, out)
        self.assertIn("the policy was not written", out)
        self.assertNotIn("a restart at", out)

    def test_without_a_time_nothing_changes(self):
        code, out, steps = self.updates("")
        self.assertEqual(code, 0, out)
        self.assertEqual(steps, ["apt-get", "apt_daily"])
        self.assertIn("after", out)

    def test_the_policy_comes_after_the_pending_updates(self):
        """The pending updates install as before, with no restart; the restart time counts only from the next run."""
        code, out, steps = self.updates("02:18")
        self.assertEqual(code, 0, out)
        self.assertEqual(steps, ["apt-get", "apt_daily", "patch_policy 02:18"])
        body = shell_function(SCRIPT, "updates")
        self.assertLess(body.index("apt_daily ||"), body.index("patch_policy ||"))

    def test_a_server_that_restarts_by_itself_already_gets_the_policy_too(self):
        """The line again on a server that has the policy: its updates wait for the daily run, as before, and the
        policy is written with the time of the new line."""
        code, out, steps = self.updates("02:18", rebooting="true")
        self.assertEqual(code, 0, out)
        self.assertEqual(steps, ["patch_policy 02:18"])

    def test_a_policy_that_could_not_be_written_stops_the_join(self):
        code, out, _ = self.updates("02:18", policy_fails=True)
        self.assertEqual(code, 1)
        self.assertIn("The fleet patch policy could not be written", out)
        self.assertNotIn("after", out)

    def test_the_time_is_hh_mm_in_utc_and_is_checked_before_anything_changes(self):
        for time in ("", "00:00", "02:18", "23:59"):
            code, out = self.check(time)
            self.assertEqual((code, out.strip().splitlines()[-1]), (0, "accepted"), time)
        for time in ("2:18", "24:00", "02:60", "0218", "02:18:00", "now", "02:18; reboot"):
            code, out = self.check(time)
            self.assertEqual(code, 1, time)
            self.assertIn("give the restart time in UTC as HH:MM", out)
            self.assertNotIn("accepted", out)
        body = shell_function(SCRIPT, "linux")
        self.assertLess(body.index('case "$REBOOT_TIME"'), body.index("    reach\n"))
        self.assertLess(body.index('case "$REBOOT_TIME"'), body.index("apt-get"))
        self.assertIn("REBOOT_TIME=${FLEET_REBOOT_TIME:-}", shell_function(SCRIPT, "main"))

    def hub_time(self, given, line="", os_id="ubuntu"):
        """hub_time with the time that the hub's answer left in server.json: (output, REBOOT_TIME after it)."""
        stubs = (f'GIVEN="{given}"\nREBOOT_TIME="{line}"\nID={os_id}\n'
                 'as_worker() { printf "%s\\n" "$GIVEN"; }\n')
        code, out = run_step("hub_time", 'hub_time\necho "REBOOT_TIME=$REBOOT_TIME"', stubs)
        self.assertEqual(code, 0, out)
        lines = out.strip().splitlines()
        return "\n".join(lines[:-1]), lines[-1].split("=", 1)[1]

    def test_the_hubs_time_comes_from_its_answer_and_wins_over_the_line(self):
        """A hub with servers.reboot_times keeps one time for each Linux server, in team.json, and gives it in its
        answer to the join: server.py writes it to server.json, and the join takes it from there. The hub's record is
        then the server's own time, also when the line carries another."""
        self.assertEqual(self.hub_time("00:04"), ("", "00:04"))
        self.assertEqual(self.hub_time("00:04", line="00:04"), ("", "00:04"))
        said, time_ = self.hub_time("00:04", line="02:18")
        self.assertEqual(time_, "00:04")
        self.assertIn("the hub keeps the restart time 00:04 for this server, so FLEET_REBOOT_TIME=02:18 is not used",
                      said)
        for given in ("", "4:00", "now", "00:04; reboot"):
            self.assertEqual(self.hub_time(given, line="02:18"), ("", "02:18"), given)
            self.assertEqual(self.hub_time(given), ("", ""), given)
        said, time_ = self.hub_time("00:04", os_id="debian")
        self.assertEqual(time_, "")
        self.assertIn("only Ubuntu takes the fleet patch policy", said)
        body = shell_function(SCRIPT, "linux")
        self.assertLess(body.index('server.py" join'), body.index("    hub_time\n"))
        self.assertLess(body.index("    hub_time\n"), body.index("    updates\n"))
        self.assertIn('"/home/$WORKER/.fleet/server.json"', shell_function(SCRIPT, "hub_time"))

    def test_a_debian_join_with_a_time_from_the_hub_goes_on_without_the_policy(self):
        """The hub does not know the system of a server that joins, so a Debian server of a fleet with
        servers.reboot_times gets a time in the hub's answer too. Only the line's own FLEET_REBOOT_TIME stops a Debian
        join, before it changes anything: the hub's time is said, and the join goes on with security updates only."""
        self.assertEqual(self.check("", "debian")[0], 0)        # the line itself has no time
        text = (shell_function(SCRIPT, "hub_time") + shell_function(SCRIPT, "updates")).replace(
            "/etc/apt/apt.conf.d/20auto-upgrades", str(self.tmp / "20auto-upgrades"))
        stubs = ('GIVEN="00:04"\nREBOOT_TIME=""\nID=debian\nAPT_LOCK_WAIT=1\n'
                 f'RAN="{self.ran}"\n'
                 + self.tool("apt-config", "echo \"AUTO_REBOOT='false'\"\n")
                 + self.tool("apt-get", f'echo apt-get >> "{self.ran}"\n')
                 + 'as_worker() { printf "%s\\n" "$GIVEN"; }\n'
                 'systemctl() { :; }\n'
                 'apt_daily() { echo apt_daily >> "$RAN"; }\n'
                 'patch_policy() { echo patch_policy >> "$RAN"; }\n')
        code, out = run_shell(text + "hub_time\nupdates\necho after\n", extra=stubs)
        self.assertEqual(code, 0, out)
        self.assertIn("the hub keeps the restart time 00:04 for this server, but only Ubuntu takes the fleet patch "
                      "policy", out)
        self.assertEqual(self.ran.read_text().splitlines(), ["apt-get", "apt_daily"])
        self.assertTrue(out.strip().endswith("after"), out)

    def test_the_policy_is_for_ubuntu_only(self):
        """It adds Ubuntu's -updates. A Debian join with a time stops before it changes anything; without one it goes
        on as before."""
        code, out = self.check("02:18", "debian")
        self.assertEqual(code, 1)
        self.assertIn("FLEET_REBOOT_TIME is for Ubuntu only", out)
        self.assertEqual(self.check("", "debian")[0], 0)


class VerifyStep(unittest.TestCase):
    """The last step of a join is `python3 fleet.py verify` (PRODUCT.md 4.1), and its lines are printed."""

    def answer(self, lines, code):
        return ('as_worker() { shift 2; printf "%s" "$LINES"; return $RC; }\n'
                f'LINES="{lines}"\nRC={code}\n')

    def test_a_healthy_machine_says_so_and_ends_with_nothing_to_fix(self):
        code, out = run_step("verify_step", "verify_step /kit as_worker\n"
                                           '[ "$ready" = yes ] || exit 1\n',
                             self.answer("  ok    disk: 41 GB free\\nREADY\\n", 0))
        self.assertEqual(code, 0, out)
        self.assertIn("ok    disk: 41 GB free", out)
        self.assertIn("this machine of the fleet is healthy", out)

    def test_a_failing_check_is_printed_with_its_fix_and_the_join_ends_in_failure(self):
        code, out = run_step("verify_step", "verify_step /kit as_worker\n"
                                           '[ "$ready" = yes ] || exit 1\n',
                             self.answer("  fail  tailnet: Tailscale is not installed, so this server is on no "
                                         "private network.  (fix: Install Tailscale on this server.)  "
                                         "(run: curl -fsSL https://tailscale.com/install.sh | sh)\\n"
                                         "NOT READY: tailnet\\n", 1))
        self.assertEqual(code, 1, out)
        self.assertIn("NOT READY: tailnet", out)
        self.assertIn("(fix: Install Tailscale on this server.)  (run: curl -fsSL", out)
        self.assertIn("NOT ready", out)

    def test_it_runs_verify_as_the_user_of_the_service_from_that_checkout(self):
        body = shell_function(SCRIPT, "verify_step")
        self.assertIn('"$2" python3 "$1/fleet.py" verify', body)

    def test_both_kinds_of_machine_end_with_it_and_the_script_carries_the_answer(self):
        for kind in ("linux", "mac"):
            self.assertIn("verify_step", shell_function(SCRIPT, kind), kind)
        self.assertIn('[ "$ready" = yes ] || exit 1', shell_function(SCRIPT, "main"))
        self.assertIn("ready=yes", TEXT)

    def test_the_header_says_what_the_last_step_is(self):
        head = TEXT.split("set -eu")[0]
        self.assertIn("fleet.py verify", head)
        self.assertIn("PRODUCT.md 4.1", head)


class NoProviderCredential(unittest.TestCase):
    """The rule that makes this product lawful to sell: a join signs in to no model provider and touches no
    credential of one. The owner signs each machine in afterwards, from the app."""

    def test_the_join_signs_in_to_nothing(self):
        for forbidden in ("setup-token", "claude login", "codex login", "auth login", "API_KEY", "OAUTH_TOKEN",
                          ".claude.json", ".codex/auth"):
            self.assertNotIn(forbidden, TEXT, f"join.sh names {forbidden}")

    def test_it_installs_no_runtime_itself(self):
        """The runtime of an agent comes with that agent, from the server service, and is signed in by the owner."""
        self.assertNotRegex(TEXT, r"runtime_install|install_runtime")

    def test_nothing_of_the_join_is_written_down_as_text(self):
        self.assertNotRegex(TEXT, r">\s*\S*(authkey|join-code|\.code)")


class MacChrome(unittest.TestCase):
    """Claude's extension for a Mac's Chrome: the file that makes Chrome fetch it from its own Web Store."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="fleet-join-chrome-"))
        self.addCleanup(shutil.rmtree, str(self.home), True)

    def test_the_join_leaves_the_file_that_chrome_reads_and_can_run_again(self):
        for _ in range(2):
            lifecycle.offer_extension(str(self.home))
        written = self.home / "Library/Application Support/Google/Chrome/External Extensions" / (lifecycle.CLAUDE_EXTENSION + ".json")
        self.assertEqual(json.loads(written.read_text()),
                         {"external_update_url": "https://clients2.google.com/service/update2/crx"})

    def test_the_server_join_writes_it_and_join_sh_does_not(self):
        self.assertNotIn("External Extensions", TEXT)
        source = (KIT / "server.py").read_text()
        self.assertIn("lifecycle.offer_extension(HOME)", source[source.index("def cmd_join"):source.index("def install_service")])


class MacRoot(unittest.TestCase):
    """The Founderizer installer runs the same line as root, behind macOS's own password dialog, so that its vault step
    needs no terminal: each step of the Mac user still runs as that user, and the checks are the installer's."""

    STUBS = ('HUB=http://100.64.0.2:8765\nHOME=/var/root\nRAN="$(mktemp)"\n'
             'id() { if [ "$1" = -u ]; then echo 0; else echo root; fi; }\n'
             'sw_vers() { echo 26.6; }\n'
             'dscl() { echo "NFSHomeDirectory: /Users/dana"; }\n'
             'reach() { :; }\n'
             'sudo() { printf "sudo %s\\n" "$*" >> "$RAN"; }\n'
             'checkout() { printf "checkout %s %s\\n" "$1" "$2" >> "$RAN"; }\n'
             'current() { printf "current %s %s\\n" "$1" "$2" >> "$RAN"; }\n'
             'mac_vault() { printf "vault %s\\n" "$MAC_USER" >> "$RAN"; }\n'
             'verify_step() { printf "verify\\n" >> "$RAN"; }\n'
             'code=ABCD\n')

    def test_the_line_as_root_needs_the_mac_user_and_runs_each_of_its_steps_as_it(self):
        if not Path("/opt/homebrew/bin/brew").exists() and not Path("/usr/local/bin/brew").exists():
            self.skipTest("this machine has no Homebrew for the step that looks for it")
        call = 'FLEET_MAC_USER=dana mac\ncat "$RAN"\necho "home=$HOME"\n'
        code, out = run_shell(shell_function(SCRIPT, "mac") + "\n" + shell_function(SCRIPT, "as_mac_user") + "\n" + call,
                              extra=self.STUBS + 'as_self() { "$@"; }\nsay() { :; }\nstop() { echo "STOP $*"; exit 1; }\n')
        self.assertEqual(code, 0, out)
        self.assertIn("checkout /Users/dana/fleet-server as_mac_user", out)
        self.assertIn("vault dana", out)
        self.assertNotIn("verify", out.replace("the checks", ""))       # the installer runs the checks itself
        self.assertIn("home=/Users/dana", out)

    def test_root_without_a_mac_user_is_refused_as_before(self):
        code, out = run_shell(shell_function(SCRIPT, "mac") + "\nmac\n",
                              extra=self.STUBS + 'say() { :; }\nstop() { echo "STOP $*"; exit 1; }\n')
        self.assertEqual(code, 1, out)
        self.assertIn("not as root", out)


def shell_value(name):
    """One top-level assignment of join.sh (NAME='...' or NAME="..."), as the line that makes it."""
    for line in TEXT.split("\n" + name + "=", 1)[1:]:
        quote = line[0]
        return name + "=" + line[:line.index(quote, 1) + 1]
    raise AssertionError(f"join.sh has no {name}")


class MacVault(unittest.TestCase):
    """A Mac's vault at its join (the owner, 28 October 2026: "it is essential that they all have access to secrets",
    and yes to one password prompt on that Mac): the signed vault of the release channel, checked, and the
    install.py inside it, run once as root."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-join-vault-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.ran = self.tmp / "ran"
        self.config = self.tmp / "config.json"          # never this Mac's own: the owner's Mac has a vault

    def step(self, build=0, sudo=0, name="mini", fleet="0123456789abcdef", track="approved"):
        stubs = (f'VAULT_CONFIG="{self.config}"\nVAULT_APP="build/Fleet Vault.app"\nVAULT_ROOT_STEP="the root step"\n'
                 'VAULT_REQUIREMENT="the requirement"\n'
                 f'HUB=http://100.64.0.2:8765\nFLEET={fleet}\nCHANNEL=https://founderizer.test\nTRACK={track}\n'
                 f'RAN={self.ran}\n'
                 f'MAC_USER=$(id -un)\npython3() {{ printf "%s\\n" "{name}"; }}\n'
                 f'vault_build() {{ printf "build %s\\n" "$1" >> "$RAN"; return {build}; }}\n'
                 f'sudo() {{ printf "sudo %s\\n" "$*" >> "$RAN"; return {sudo}; }}\n')
        return run_step("mac_vault", 'mac_vault\necho "ready=$ready"\n', stubs)

    def test_a_mac_without_a_vault_gets_the_checked_one_with_one_password_prompt(self):
        for track in ("approved", "early"):         # the root step gets the fleet's track last
            with self.subTest(track=track):
                self.ran.unlink(missing_ok=True)
                code, out = self.step(track=track)
                self.assertEqual(code, 0, out)
                ran = self.ran.read_text().splitlines()
                self.assertEqual(len(ran), 2, ran)
                self.assertTrue(ran[1].startswith("sudo /bin/sh -c the root step sh "), ran)
                self.assertTrue(ran[1].endswith(
                    '/build/Fleet Vault.app ' + __import__("getpass").getuser() + ' mini http://100.64.0.2:8765 '
                    '0123456789abcdef https://founderizer.test the requirement ' + track), ran[1])
                self.assertLess(out.index("macOS asks once for the password"),
                                out.index("installed, with the fleet's own"))
                self.assertIn("ready=yes", out)

    def test_a_mac_whose_vault_is_there_keeps_it_and_asks_for_nothing(self):
        self.config.write_text("{}")
        code, out = self.step()
        self.assertEqual((code, self.ran.exists()), (0, False), out)
        self.assertIn("installed already", out)

    def test_no_signed_vault_no_name_or_no_fleet_asks_for_nothing_and_says_so(self):
        for kwargs, words in (({"build": 1}, "gave no signed vault"), ({"name": ""}, "no name or no release channel"),
                              ({"fleet": ""}, "no name or no release channel")):
            with self.subTest(**kwargs):
                self.ran.unlink(missing_ok=True)
                code, out = self.step(**kwargs)
                self.assertEqual(code, 0, out)
                self.assertIn(words, out)
                self.assertIn("ready=no", out)
                self.assertNotIn("sudo", self.ran.read_text() if self.ran.exists() else "")

    def test_a_refused_root_step_ends_the_join_in_failure(self):
        code, out = self.step(sudo=1)
        self.assertEqual(code, 0, out)
        self.assertIn("the lines above say why", out)
        self.assertIn("ready=no", out)

    def build(self, url, digest_of=b"zip", track="approved"):
        """vault_build with stub downloads: the manifest names `url` and the SHA-256 of `digest_of`."""
        import hashlib
        digest = hashlib.sha256(digest_of).hexdigest()
        stubs = (shell_value("VAULT_APP") + "\nCHANNEL=https://founderizer.test\nFLEET=0123456789abcdef\n"
                 f"TRACK={track}\nRAN={self.ran}\n"
                 'curl() { printf "curl %s\\n" "$*" >> "$RAN"; while [ "$1" != -o ]; do shift; done; '
                 'printf zip > "$2"; }\n'
                 f'plutil() {{ case "$2" in url) printf "%s" "{url}" ;; sha256) printf "{digest}" ;; esac; }}\n'
                 'ditto() { mkdir -p "$4/Founderizer.app/Contents/Library/Fleet Vault.app"; }\n')
        return run_step("vault_build", f'vault_build {self.tmp}\n', stubs)

    def test_the_build_is_the_channels_own_by_its_sha256(self):
        code, out = self.build("https://founderizer.test/downloads/Founderizer-0.1.68.zip")
        self.assertEqual(code, 0, out)
        ran = self.ran.read_text()
        self.assertIn("-H Founderizer-Fleet: 0123456789abcdef -o", ran)
        self.assertIn("https://founderizer.test/releases/app", ran)
        for url, data in (("https://elsewhere.test/Founderizer.zip", b"zip"),
                          ("https://founderizer.test/../Founderizer.zip", b"zip"),
                          ("https://founderizer.test/downloads/Founderizer.zip", b"another zip")):
            with self.subTest(url=url):
                self.assertNotEqual(self.build(url, data)[0], 0)

    def test_an_early_fleet_asks_for_the_early_track_and_every_other_value_for_the_approved_one(self):
        """PRODUCT.md 4.3, "Two tracks": the manifest of the fleet's own track, as the vault's updater asks for it.
        Only the exact word early asks for the early track; anything else, a placeholder no hub filled included,
        asks for the approved track."""
        for track, asked in (("early", "https://founderizer.test/releases/app?track=early"),
                             ("approved", "https://founderizer.test/releases/app"),
                             ("__FLEET_TRACK__", "https://founderizer.test/releases/app")):
            with self.subTest(track=track):
                self.ran.unlink(missing_ok=True)
                code, out = self.build("https://founderizer.test/downloads/Founderizer-0.1.113.zip", track=track)
                self.assertEqual(code, 0, out)
                self.assertEqual(self.ran.read_text().splitlines()[0].rsplit(" ", 1)[1], asked)

    def root_step(self, signed=0, installer=True, track="approved"):
        """VAULT_ROOT_STEP itself, as this user, with stubs for what only root may do."""
        app = self.tmp / "user" / "Fleet Vault.app"
        (app / "Contents/Resources").mkdir(parents=True)
        if installer:
            (app / "Contents/Resources/install.py").write_text("installer")
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        for name, body in (("chown", "exit 0"), ("codesign", f'echo "codesign $*" >> {self.ran}; exit {signed}'),
                           ("python3", f'echo "python3 $*" >> {self.ran}')):
            (bin_ / name).write_text(f"#!/bin/sh\n{body}\n")
            (bin_ / name).chmod(0o755)
        # The text between the quotes is what sh -c gets; root's own Python is the stub here.
        step = shell_value("VAULT_ROOT_STEP").split("=", 1)[1][1:-1].replace("/usr/bin/python3", "python3")
        done = subprocess.run(["sh", "-c", step, "sh", str(app), "dana", "mini", "http://100.64.0.2:8765",
                               "0123456789abcdef", "https://founderizer.test", "the requirement", track],
                              capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                              env={"PATH": f"{bin_}:/usr/bin:/bin"})
        return done.returncode, done.stdout + done.stderr, app

    def test_the_root_step_runs_the_installer_of_its_own_checked_copy(self):
        code, out, app = self.root_step()
        self.assertEqual(code, 0, out)
        codesign, python = self.ran.read_text().splitlines()
        self.assertIn("--verify --deep --strict -R =the requirement /tmp/fleet-vault-root.", codesign)
        stage = codesign.split(" -R =the requirement ", 1)[1]
        self.assertNotIn(str(app), codesign)                # never the copy this user can change
        self.assertTrue(python.startswith(f"python3 {stage}/Contents/Resources/install.py --app {stage} --user dana "
                                          "--agent mini --hub http://100.64.0.2:8765 --store --fleet 0123456789abcdef "
                                          "--channel https://founderizer.test"), python)
        self.assertFalse(Path(stage).exists())              # root's copy goes when the step ends

    def test_only_an_early_fleet_gives_the_installer_a_track(self):
        """The early track reaches the vault's updater only through update.json, which only install.py writes, as
        root. An approved fleet passes no --track: the install.py of an approved build may be older than the flag,
        and it refuses an argument it does not know. Its updater then takes the approved track, the default."""
        for track, passed in (("early", " --track early"), ("approved", ""), ("__FLEET_TRACK__", "")):
            with self.subTest(track=track):
                shutil.rmtree(self.tmp / "user", True)
                shutil.rmtree(self.tmp / "bin", True)
                self.ran.unlink(missing_ok=True)
                code, out, _ = self.root_step(track=track)
                self.assertEqual(code, 0, out)
                python = self.ran.read_text().splitlines()[1]
                self.assertTrue(python.endswith(" --channel https://founderizer.test" + passed), python)

    def test_a_vault_that_fails_its_check_or_carries_no_installer_runs_nothing(self):
        for kwargs, words in (({"signed": 1}, ""), ({"installer": False}, "carries no installer yet")):
            with self.subTest(**kwargs):
                shutil.rmtree(self.tmp / "user", True)
                shutil.rmtree(self.tmp / "bin", True)
                self.ran.unlink(missing_ok=True)
                code, out, _ = self.root_step(**kwargs)
                self.assertNotEqual(code, 0, out)
                self.assertIn(words, out)
                self.assertNotIn("python3", self.ran.read_text() if self.ran.exists() else "")

    def test_the_mac_join_takes_the_vault_before_it_verifies_and_asks_for_root_nowhere_else(self):
        body = shell_function(SCRIPT, "mac")
        self.assertLess(body.index("mac_vault"), body.index("verify_step "))
        self.assertNotIn("sudo", body)
        self.assertEqual([n for n in ("checkout", "current", "reach", "verify_step", "vault_build")
                          if "sudo" in shell_function(SCRIPT, n)], [])


if __name__ == "__main__":
    unittest.main()
