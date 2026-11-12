"""Each agent's session runs as its own OS user (PRODUCT.md 4.1 and "What the move to per-agent users decided").

Three things are proved here, and none of them makes a user on this machine: every command of the root helper goes
to a stub that records it, so the helper's own refusals and its lines are measured; the sudoers file is measured as
text; and the names that three programs share (`fleet-<agent>`, the helper's path, the group) are pinned to the one
place they come from, because a second copy of a name is how two programs come to disagree.

The per-user readings of `fleet.py verify` are in test_verify.AgentUsers, and the agent-add path is in
test_servers.ServerService. A real Ubuntu with systemd is the only place the users themselves are made; the lane's
note says what that run proved.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

import hub
import hubsetup
import server
import verify

KIT = Path(__file__).resolve().parent
REPO = "git://100.80.1.2/fleet-pilot.git"       # the configuration ref as the hub serves it to a machine
# Everything the helper runs: a stub for each, so the script can be run here without making anything.
TOOLS = ("id", "useradd", "passwd", "groupadd", "usermod", "chown", "chmod", "gpasswd", "loginctl")


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite([*(Helper(n) for n in Helper.__dict__ if n.startswith("test_")),
                               *(Sudoers(n) for n in Sudoers.__dict__ if n.startswith("test_")),
                               *(InPlace(n) for n in InPlace.__dict__ if n.startswith("test_")),
                               *(OneName(n) for n in OneName.__dict__ if n.startswith("test_"))])


class Helper(unittest.TestCase):
    """`/usr/local/sbin/fleet-agent-user <fleet-agent>`: the one root command of a machine, which the server service
    may run because it has no root of its own."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-agent-helper-"))
        self.addCleanup(subprocess.run, ["rm", "-rf", str(self.tmp)])
        self.script = self.tmp / "fleet-agent-user"
        self.script.write_text(hubsetup.helper_script())
        self.script.chmod(0o755)
        self.log, self.there, self.members = self.tmp / "ran", self.tmp / "users", self.tmp / "members"
        self.stubs = self.tmp / "bin"
        self.stubs.mkdir()
        for tool in TOOLS:
            body = ""
            if tool == "id":        # `id -u` alone answers 0, so the script's own root check passes here
                body = (f'if [ "$#" = 1 ] && [ "$1" = -u ]; then echo 0; exit 0; fi\n'
                        f'if [ "$1" = -u ]; then grep -qx "$2" {self.there} 2>/dev/null || exit 1; echo 4001; fi\n'
                        f'if [ "$1" = -nG ]; then printf "%s" "$2"; grep -qx "$2" {self.members} 2>/dev/null && '
                        f'printf " {hubsetup.AGENT_GROUP}"; echo; fi\n')
            if tool == "useradd":   # the user exists from here on, as it does on a real machine
                body = f'for a in "$@"; do u=$a; done; printf "%s\\n" "$u" >> {self.there}\n'
            if tool == "usermod":   # and is in the agents' group once usermod put it there
                body = f'for a in "$@"; do u=$a; done; printf "%s\\n" "$u" >> {self.members}\n'
            one = self.stubs / tool
            one.write_text(f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> {self.log}\n{body}exit 0\n')
            one.chmod(0o755)

    def not_root(self):
        """A stub `id` that answers a uid which is not 0, so the script's own root check is measured here whether
        or not the test itself runs as root."""
        folder = self.tmp / "notroot"
        folder.mkdir(exist_ok=True)
        (folder / "id").write_text('#!/bin/sh\nif [ "$#" = 1 ] && [ "$1" = -u ]; then echo 1000; exit 0; fi\nexit 1\n')
        (folder / "id").chmod(0o755)
        return folder

    def run_helper(self, *args, root=True):
        tools = [str(self.stubs)] if root else [str(self.not_root()), str(self.stubs)]
        done = subprocess.run(["sh", str(self.script), *args], capture_output=True, text=True,
                              env=dict(os.environ, PATH=os.pathsep.join(tools + [os.environ["PATH"]])))
        return done.returncode, done.stdout + done.stderr

    def lines(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def changes(self):
        """What it ran that changes this machine: a reading of the password database changes nothing."""
        return [line for line in self.lines() if not line.startswith("id ")]

    def test_the_script_is_valid_shell(self):
        subprocess.run(["sh", "-n", str(self.script)], check=True, capture_output=True)

    def test_it_makes_the_user_of_one_agent(self):
        code, said = self.run_helper("fleet-writer")
        self.assertEqual(code, 0, said)
        self.assertIn("fleet-writer is the OS user of that agent", said)
        ran = "\n".join(self.lines())
        for wanted in ("useradd --create-home --shell /bin/bash --user-group fleet-writer",
                       "passwd -l fleet-writer", "groupadd -f " + hubsetup.AGENT_GROUP,
                       "usermod -aG %s fleet-writer" % hubsetup.AGENT_GROUP,
                       "chown fleet-writer:fleet-writer /home/fleet-writer", "chmod 700 /home/fleet-writer",
                       "loginctl enable-linger fleet-writer"):
            self.assertIn(wanted, ran)
        for group in ("sudo", "admin", "wheel"):
            self.assertIn(f"gpasswd -d fleet-writer {group}", ran)

    def test_it_needs_root_and_does_nothing_without_it(self):
        code, said = self.run_helper("fleet-writer", root=False)
        self.assertEqual((code, self.changes()), (1, []))
        self.assertIn("needs root", said)

    def test_it_takes_one_argument_and_nothing_else(self):
        for args in ((), ("fleet-writer", "fleet-reader")):
            code, said = self.run_helper(*args)
            self.assertEqual((code, self.changes()), (2, []), args)
            self.assertIn("one argument", said)

    def test_it_refuses_anything_that_is_not_an_agent_user_of_a_fleet(self):
        """The argument is the only input, so it is read before any line that changes this machine."""
        for bad in ("root", "fleet", "fleet-", "fleet-Writer", "fleet-w", "fleet-writer;id", "fleet-writer ",
                    "../root", "writer", "fleet-" + "w" * 27, "FLEET-writer", "fleet-9writer", "fleet-writer/x"):
            code, said = self.run_helper(bad)
            self.assertEqual((code, self.changes()), (2, []), bad)
            self.assertIn("is no agent user of a fleet", said)

    def test_it_takes_every_agent_name_this_fleet_can_give_a_user(self):
        """The helper's own pattern and hubsetup.agent_user must agree, or an agent the hub allows gets no user."""
        for name in ("ab", "writer", "a-b-c", "x9", "w" * 25):
            user = hubsetup.agent_user(name)
            self.assertTrue(hub.AGENT_NAME.fullmatch(name), name)
            self.assertEqual(self.run_helper(user)[0], 0, user)
            self.log.unlink()

    def test_the_longest_name_the_helper_takes_is_the_longest_user_a_system_makes(self):
        longest = "w" * (hubsetup.USER_LIMIT - len("fleet-"))
        self.assertEqual(len(hubsetup.agent_user(longest)), hubsetup.USER_LIMIT)
        # the hub allows 31 characters, so the installer refuses the name instead of making a user that is cut off
        with self.assertRaises(hubsetup.Stop):
            hubsetup.agent_user("w" * (hubsetup.USER_LIMIT - len("fleet-") + 1))

    def test_it_leaves_alone_a_user_of_this_machine_that_is_no_agents(self):
        """DevOps plan 0.3: the service user may ask root for an agent's user, and for nothing more. A user of this
        machine outside the agents' group, a system user or a person, is never put in that group, so the service
        user cannot become it with its sudoers line."""
        self.there.write_text("fleet-somebody\n")              # there already, and in no agents' group
        code, said = self.run_helper("fleet-somebody")
        self.assertEqual(code, 3, said)
        self.assertIn("no agent's, so it stays as it is", said)
        self.assertEqual(self.changes(), [])

    def test_it_never_makes_the_vaults_own_users(self):
        for user in hubsetup.RESERVED_USERS:
            with self.subTest(user=user):
                code, said = self.run_helper(user)
                # a name outside the agents' own form (the central vault's founderizer-vault) stops one line earlier
                self.assertIn(code, (2, 3), said)
                self.assertTrue("never an agent's" in said or "is no agent user of a fleet" in said, said)
                self.assertEqual(self.changes(), [])

    def test_a_second_run_changes_nothing_that_is_already_right(self):
        """Every line of it reads first, so the server service can call it for an agent it installs again."""
        self.assertEqual(self.run_helper("fleet-writer")[0], 0)
        self.log.unlink()
        self.assertEqual(self.run_helper("fleet-writer")[0], 0)
        self.assertNotIn("useradd", "\n".join(self.changes()), "it made the user a second time")
        self.assertIn("id -u fleet-writer", "\n".join(self.lines()))
        self.assertEqual(self.there.read_text().split(), ["fleet-writer"])


class Sudoers(unittest.TestCase):
    """`/etc/sudoers.d/fleet-agents`: what the machine's service user may do with root, and nothing more."""

    def text(self, user="fleet"):
        return hubsetup.sudoers_text(user)

    def rules(self, user="fleet"):
        return [line for line in self.text(user).splitlines() if line and not line.startswith("#")]

    def test_it_gives_three_rights_and_no_more(self):
        self.assertEqual(self.rules(), [f"fleet ALL=(root) NOPASSWD: {hubsetup.HELPER}",
                                        f'fleet ALL=(root) NOPASSWD: {hubsetup.VAULT_UPDATE} ""',
                                        f"fleet ALL=(%{hubsetup.AGENT_GROUP}) NOPASSWD: ALL"])

    def test_the_vault_right_is_written_for_no_arguments_at_all(self):
        """sudoers(5): a command written with no argument list may be run with any arguments the caller chooses,
        and `""` is how it says "with no arguments". The program refuses an argument itself too; this is the layer
        that holds whatever the program on the machine turns out to be."""
        line = [one for one in self.rules() if hubsetup.VAULT_UPDATE in one]
        self.assertEqual(line, [f'fleet ALL=(root) NOPASSWD: {hubsetup.VAULT_UPDATE} ""'])
        self.assertNotIn("*", line[0])          # never a wildcard: that is an argument the caller chooses

    def test_the_root_rights_are_the_two_helpers_and_name_no_other_command(self):
        """Each root right is one mechanical act that takes nothing from the caller: one agent user name, which
        the first helper checks itself, and no argument at all for the second, which fetches what it installs. A
        root right that took a path, a value or a command would be a way for this user to run its own code as
        root, which is the one thing a root right of it must not become."""
        root = [line for line in self.rules() if "(root)" in line]
        self.assertEqual([line.split("NOPASSWD: ")[1] for line in root],
                         [hubsetup.HELPER, hubsetup.VAULT_UPDATE + ' ""'])
        for line in root:
            for never in ("ALL=(ALL)", "ALL=(ALL:ALL)", "sh", "bash", "su ", "/bin/", "*"):
                self.assertNotIn(never, line)

    def test_the_other_right_is_the_agent_users_and_never_root(self):
        """The service user becomes an agent to install it and to read it; it may not become root that way."""
        line = [line for line in self.rules() if "(root)" not in line][0]
        self.assertIn(f"(%{hubsetup.AGENT_GROUP})", line)
        self.assertNotIn("(root)", line)
        self.assertNotIn("(ALL", line)

    def test_it_names_the_service_user_it_was_written_for(self):
        self.assertEqual([r.split()[0] for r in self.rules("claude")], ["claude", "claude", "claude"])

    def test_it_says_in_the_file_what_the_three_rights_are_for(self):
        """The owner reads this file on their own server, so it carries its own reason -- including why a second
        root right is not a way out of this user, which is the decision a reader of this file meets first."""
        said = self.text()
        self.assertTrue(said.startswith("#"))
        for wanted in ("Founderizer", "hubsetup.py", hubsetup.AGENT_GROUP, "may not become root",
                       "vault broker", "takes no argument", "nothing from the caller"):
            self.assertIn(wanted, said)


class InPlace(unittest.TestCase):
    """`hubsetup.agent_helper`: it puts the helper, the group and the sudoers file in place, and nothing else."""

    def setUp(self):
        self.ran, self.files = [], {}

    def shell(self, script):
        self.ran.append(script)
        return 0, "", ""

    def read(self, path):
        if path not in self.files:
            raise OSError(2, "no such file")
        return self.files[path]

    def there(self, user="fleet"):
        self.files = {hubsetup.HELPER: hubsetup.helper_script(),
                      hubsetup.VAULT_UPDATE: hubsetup.vault_program_script(REPO),
                      hubsetup.SUDOERS: hubsetup.sudoers_text(user),
                      hubsetup.RELEASE_CHECK: (KIT / "releases.py").read_text(),
                      hubsetup.RELEASE_KEYS: (KIT / "release-key.pub").read_text(),
                      hubsetup.EARLY_KEYS: (KIT / "early-key.pub").read_text()}

    def test_it_writes_all_three_files_and_makes_the_group(self):
        self.assertEqual(hubsetup.agent_helper("fleet", repo=REPO, run=self.shell, read=self.read), "made")
        script = "\n".join(self.ran)
        self.assertIn(f"groupadd -f {hubsetup.AGENT_GROUP}", script)
        self.assertIn(f"install -o root -g root -m 755", script)
        self.assertIn(hubsetup.HELPER, script)
        self.assertIn(hubsetup.VAULT_UPDATE, script)
        self.assertIn(f"install -o root -g root -m 440", script)
        self.assertIn(hubsetup.SUDOERS, script)

    def test_the_rights_and_the_commands_they_name_are_written_together(self):
        """One run puts both root commands and the sudoers file in place, so the rights and the commands they
        name can never be read apart: a sudoers line that names a command this machine does not have, or a command
        with no line, is a machine nobody can reason about."""
        hubsetup.agent_helper("fleet", repo=REPO, run=self.shell, read=self.read)
        script = "\n".join(self.ran)
        self.assertLess(script.index(hubsetup.VAULT_UPDATE), script.index(hubsetup.SUDOERS))

    def test_visudo_reads_the_file_before_it_is_moved_in(self):
        """A file that sudo cannot parse takes sudo away from the whole machine, so it is checked first."""
        hubsetup.agent_helper("fleet", repo=REPO, run=self.shell, read=self.read)
        script = "\n".join(self.ran)
        self.assertLess(script.index("visudo -cqf"), script.index(hubsetup.SUDOERS))

    def test_the_two_files_it_writes_are_the_two_this_version_makes(self):
        """What it writes is read back by the same two functions, so a later version is put in place by a re-run."""
        written = {}

        def shell(script):
            for _mode, source, target in re.findall(r"install -o root -g root -m (\d+) (\S+) (\S+)", script):
                written[target] = Path(source).read_text()
            return 0, "", ""
        hubsetup.agent_helper("fleet", repo=REPO, run=shell, read=self.read)
        self.assertEqual(written, {hubsetup.HELPER: hubsetup.helper_script(),
                                   hubsetup.VAULT_UPDATE: hubsetup.vault_program_script(REPO),
                                   hubsetup.SUDOERS: hubsetup.sudoers_text("fleet"),
                                   # DevOps plan 0.3: root's own copies of the check and the keys of a release
                                   hubsetup.RELEASE_CHECK: (KIT / "releases.py").read_text(),
                                   hubsetup.RELEASE_KEYS: (KIT / "release-key.pub").read_text(),
                                   # PRODUCT.md 4.3 "Two tracks": and the early keys, which a fleet that takes
                                   # releases early took a release by
                                   hubsetup.EARLY_KEYS: (KIT / "early-key.pub").read_text()})

    def test_a_second_run_with_both_files_in_place_changes_nothing(self):
        self.there()
        self.assertEqual(hubsetup.agent_helper("fleet", repo=REPO, run=self.shell, read=self.read), "there")
        self.assertEqual(self.ran, [])

    def test_a_file_from_another_version_is_written_again(self):
        self.there()
        self.files[hubsetup.SUDOERS] = "fleet ALL=(ALL) NOPASSWD: ALL\n"
        self.assertEqual(hubsetup.agent_helper("fleet", repo=REPO, run=self.shell, read=self.read), "made")
        self.assertTrue(self.ran)

    def test_check_mode_says_what_it_would_write_and_runs_nothing(self):
        self.assertEqual(hubsetup.agent_helper("fleet", repo=REPO, check=True, run=self.shell, read=self.read), "would make")
        self.assertEqual(self.ran, [])

    def test_a_step_that_fails_stops_the_install(self):
        with self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.agent_helper("fleet", repo=REPO, run=lambda script: (1, "", "visudo: parse error"), read=self.read)
        self.assertIn("visudo: parse error", str(stopped.exception))

    def test_it_leaves_no_temporary_file_of_its_own(self):
        kept = []
        hubsetup.agent_helper("fleet", repo=REPO,
                              run=lambda script: (kept.extend(re.findall(r"(/\S+fleet-agent-helper-\S+)",
                                                                        script)), (0, "", ""))[1],
                              read=self.read)
        self.assertTrue(kept)
        for path in kept:
            self.assertFalse(os.path.exists(path), path)


class OneName(unittest.TestCase):
    """The names that `hubsetup.py`, `server.py` and `verify.py` share. A second copy of one of these is how two
    programs come to disagree about which user holds an agent, so each copy is pinned to the one place it is from."""

    def test_the_agent_user_is_one_convention(self):
        self.assertEqual(hubsetup.AGENT_USER, "fleet-%s")
        self.assertEqual(server.AGENT_USER, hubsetup.AGENT_USER)
        self.assertEqual(verify.AGENT_USER, hubsetup.AGENT_USER)

    def test_the_helper_is_one_path(self):
        self.assertEqual(hubsetup.HELPER, "/usr/local/sbin/fleet-agent-user")
        self.assertEqual(server.AGENT_HELPER, hubsetup.HELPER)

    def test_the_vault_helper_and_the_program_it_installs_are_one_path_each(self):
        """The server service runs the second root command and reads the program it installs, so both names are
        taken from the installer that writes them: a second copy of either is how the service comes to ask for
        nothing while the broker is behind."""
        self.assertEqual(hubsetup.VAULT_UPDATE, "/usr/local/sbin/fleet-vault-program")
        self.assertEqual(server.VAULT_HELPER, hubsetup.VAULT_UPDATE)
        self.assertEqual(server.VAULT_PROGRAM, hubsetup.VAULT_LIB + "/vault.py")

    def test_both_installers_put_the_helper_in_place_and_make_no_user_themselves(self):
        for script in (KIT / "hub.sh", KIT / "join.sh"):
            text = script.read_text()
            self.assertIn('hubsetup.py" agent-helper', text, script.name)
            # And with the address of the configuration ref, which the vault helper fetches the broker's program
            # from: without it that helper refuses for ever, and a release that changes vault.py leaves this
            # machine's broker behind with nothing saying why.
            call = re.search(r'agent-helper --user "\$\w+" --repo "(\S+?)"', text)
            self.assertTrue(call, f"{script.name} runs agent-helper without --repo")
            self.assertRegex(call.group(1), r'^(\$REPO|git://\$address/\$repo_name\.git)$')
            self.assertIn('hubsetup.py" agent-users', text, script.name)
            self.assertNotIn("useradd --create-home --shell /bin/bash --user-group fleet-", text, script.name)
            # the one place that writes the helper and the sudoers file is hubsetup.agent_helper
            self.assertNotIn("install -o root", text, script.name)

    def test_the_hub_installer_installs_each_agent_under_its_own_user(self):
        text = (KIT / "hub.sh").read_text()
        self.assertIn("as_agent() {", text)
        self.assertIn('runuser -u "$agent_as"', text)
        self.assertIn('hubsetup.py" agent-list', text)
        for wanted in ('fleet.py" service "$agent"', 'systemctl --user enable "fleet-$agent.service"',
                       'hubsetup.py" runtime --runtime "$agent_runtime"'):
            self.assertIn(wanted, text)

    def test_a_mac_keeps_one_user_for_its_agents(self):
        """A Mac agent's service is a LaunchAgent of a desktop session, so a second user would have to be logged in
        at the screen (PRODUCT.md P2). The join script says so, and server.py makes no user there."""
        text = (KIT / "join.sh").read_text()
        self.assertIn("No OS user for each agent on a Mac", text)
        service = server.Service.__dict__
        self.assertIn("keeps one user for its agents", service["agent_user"].__doc__)
        self.assertIsNone(server.Service.agent_user(_Mac(), "writer"))


class _Mac:
    """Enough of a Service to ask it which user holds an agent on a Mac."""
    platform = "darwin"

    @staticmethod
    def users(_user):
        return 4001, "/Users/dana"


if __name__ == "__main__":
    unittest.main()
