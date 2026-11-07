#!/bin/sh
# Founderizer target host setup (owner feature target_servers). The hub served it at GET /place with its own address
# in HUB, and the owner ran it as root on the host that holds a target, with the one line from Founderizer (Targets,
# Add server); FLEET_PLACE held the one-time code.
#
# Unused since Targets left the hub on 24 October 2026: no hub serves this script or answers its calls any more
# (POST /place/plan, GET /place/helper, POST /place/done), so it stops at the end of this file, before it calls one or
# changes this host. main stays, with place.py, for the central vault that comes next (publish.py).
#
# A key in a machine's vault reaches the place where an application reads it through one helper on this host,
# place.py, which the vault may run as the forced command of one SSH key and in no other way. This puts that helper
# here, gives the vault's key the one line of this host's authorized_keys file that runs it, and tells the hub this
# host's own public key, so the vault knows which host it is talking to. Those three were a page of pasted root
# commands, and the host key was typed into the app by hand.
#
# Nothing of a secret comes near this script. The code opens this one host's setup, the hub answers with the line and
# the checksum of the helper, and the value of a key never leaves the vault: it travels on the vault's own SSH
# connection to the helper this installs, and never through the hub or this script.
#
# Safe to run again, and run again is how a host is brought up to date: the script replaces its own line instead of
# adding a second one, so a second target on this host needs a new line from Founderizer and nothing else.
set -eu

HUB="__FLEET_HUB__"
PROGRAM=/usr/local/lib/fleet-place/place.py
SHELLS="/bin/sh /bin/bash /bin/dash /bin/zsh /usr/bin/sh /usr/bin/bash /usr/bin/zsh"

say() { printf 'Founderizer: %s\n' "$*"; }
stop() { printf 'Founderizer target setup stopped: %s\n' "$*" >&2; exit 1; }

# The hub call, as a program in a file: the code goes to it on standard input, so it stands in no argument, no URL
# and no process list. It prints the answer as one key=value line each, the line itself base64 so that its quotes and
# spaces survive the shell.
helper_program() {
    cat <<'PY'
import base64, json, os, sys, urllib.error, urllib.request

hub, step = sys.argv[1], sys.argv[2]
body = {"code": sys.stdin.readline().strip()}
for pair in sys.argv[3:]:
    name, _, value = pair.partition("=")
    body[name] = value
request = urllib.request.Request(hub + "/place/" + step, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "X-Fleet-Client": "fleet-place/1"}, method="POST")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(request, timeout=30) as answer:
        got = json.loads(answer.read() or b"{}")
except urllib.error.HTTPError as e:
    try:
        said = json.loads(e.read() or b"{}").get("error") or ""
    except ValueError:
        said = ""
    sys.exit(said or f"the hub answered HTTP {e.code}")
except (urllib.error.URLError, OSError, ValueError) as e:
    sys.exit(f"the hub could not be reached ({type(e).__name__})")
for name, value in sorted(got.items()):
    if name == "line":
        print("line_b64=" + base64.b64encode(value.encode()).decode())
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        print(f"{name}={value}")
    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
        print(f"{name}=" + ",".join(value))
PY
}

# One line of this host's authorized_keys file, put in place without touching another: every line that carries this
# same key goes, the new one is appended, and the file is replaced whole, never left half written.
keys_program() {
    cat <<'PY'
import base64, os, stat, sys

path, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
line = base64.b64decode(sys.argv[4]).decode()
key = line.split()[-2] if len(line.split()) >= 2 else ""
if not key:
    sys.exit("the hub gave no key for this host's line")
folder = os.path.dirname(path)
if not os.path.isdir(folder):
    os.mkdir(folder, 0o700)
os.chown(folder, uid, gid)
os.chmod(folder, 0o700)
try:
    with open(path, encoding="utf-8") as f:
        there = f.read(1 << 20).splitlines()
except FileNotFoundError:
    there = []
except (OSError, UnicodeError) as e:
    sys.exit(f"{path} cannot be read ({type(e).__name__})")
kept = [l for l in there if key not in l]
if kept + [line] == there:
    print("already there")
    raise SystemExit(0)
temp = path + ".fleet-place"
with open(temp, "w", encoding="utf-8") as f:
    f.write("".join(l + "\n" for l in kept + [line]))
os.chown(temp, uid, gid)
os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
os.replace(temp, path)
print("one line of ours replaced" if len(kept) != len(there) else "appended")
PY
}

reach() {
    curl -fsS -m 10 "$HUB/health" >/dev/null 2>&1 || stop "This host cannot reach the Founderizer hub at $HUB. It \
needs the hub's address to take the helper and to tell Founderizer this host's own key."
}

user_step() {   # $1: the user that owns what the helper writes. sshd runs a forced command through the user's shell,
                # so a user with none runs nothing; one that this script makes gets /bin/bash.
    if ! id -u "$1" >/dev/null 2>&1; then
        [ "$1" != root ] || stop "This host has no root account."
        say "the user $1, which owns what the helper writes"
        useradd --create-home --shell /bin/bash --user-group "$1" \
            || stop "The user $1 could not be made on this host."
        return 0
    fi
    shell=$(getent passwd "$1" | cut -d: -f7)
    for ok in $SHELLS; do
        [ "$shell" = "$ok" ] && return 0
    done
    stop "The user $1 has the shell $shell, and sshd runs this helper through the user's shell, so it would run \
nothing. Give that user a login shell, then run the line again: usermod -s /bin/bash $1"
}

helper_step() { # $1: the SHA-256 that the hub gave. The helper is checked against it before it becomes a program that
                # this host runs as root, because it comes over the network.
    curl -fsS -m 60 -o "$work/place.py" "$helper" || stop "The place helper could not be taken from $helper."
    got=$(sha256sum "$work/place.py" | cut -d' ' -f1)
    [ "$got" = "$1" ] || stop "The place helper that this hub serves is not the one it named ($got, not $1). Nothing \
was installed."
    install -d -o root -g root -m 755 "${PROGRAM%/*}" || stop "${PROGRAM%/*} could not be made."
    install -o root -g root -m 644 "$work/place.py" "$PROGRAM" || stop "$PROGRAM could not be installed."
    say "the place helper in $PROGRAM, root with mode 644, checked against the hub's own reading of it"
}

host_key() {    # This host's own public key, as its .pub file has it and without the name at the end: the vault pins
                # it and talks to this host and to no other. The keys that this host's own sshd offers, so that a
                # host whose keys are not in /etc/ssh is read right; ed25519 first, which is what sshd offers first.
    files=$(printf '%s\n' "$sshd_conf" | sed -n 's/^hostkey //p')
    for kind in ed25519 ecdsa rsa; do
        for one in $files "/etc/ssh/ssh_host_${kind}_key"; do
            case "$one" in *"_${kind}_"*) ;; *) continue ;; esac
            [ -s "$one.pub" ] || continue
            awk '{print $1 " " $2; exit}' "$one.pub"
            return 0
        done
    done
    stop "This host has no public SSH host key that its sshd offers. Its sshd makes one when it is installed."
}

sshd_step() {   # Two settings of this host's sshd that would make the line do nothing. Said, not changed: this host
                # is the owner's.
    [ -z "$sshd_conf" ] && return 0
    printf '%s\n' "$sshd_conf" | grep -qi '^pubkeyauthentication yes' \
        || say "WARNING: this host's sshd has public key authentication off, so the vault cannot sign in. Turn it on \
in /etc/ssh/sshd_config (PubkeyAuthentication yes), then restart sshd."
    printf '%s\n' "$sshd_conf" | grep -qi '^authorizedkeysfile.*\.ssh/authorized_keys' \
        || say "WARNING: this host's sshd does not read ~/.ssh/authorized_keys, so it will not find the line that \
this put there. Check AuthorizedKeysFile in /etc/ssh/sshd_config."
}

main() {
    [ -n "${FLEET_PLACE:-}" ] || stop "No code. Copy the whole line from Founderizer: Targets, Add server."
    code=$FLEET_PLACE
    unset FLEET_PLACE
    [ "$(id -u)" = 0 ] || stop "Run the line as root (for example after sudo -i)."
    command -v curl >/dev/null 2>&1 || stop "curl is required."
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null \
        || stop "Python 3.8 or later is required: the place helper is a Python program."
    sshd_conf=$(sshd -T 2>/dev/null || true)
    reach

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    helper_program > "$work/api.py"
    keys_program > "$work/keys.py"

    plan=$(printf '%s\n' "$code" | python3 "$work/api.py" "$HUB" plan) \
        || stop "Founderizer did not give this host its setup. $plan"
    user=$(printf '%s\n' "$plan" | sed -n 's/^user=//p')
    sha=$(printf '%s\n' "$plan" | sed -n 's/^sha256=//p')
    helper=$(printf '%s\n' "$plan" | sed -n 's/^helper=//p')
    line_b64=$(printf '%s\n' "$plan" | sed -n 's/^line_b64=//p')
    program=$(printf '%s\n' "$plan" | sed -n 's/^program=//p')
    targets=$(printf '%s\n' "$plan" | sed -n 's/^targets=//p')
    [ -n "$user" ] && [ -n "$sha" ] && [ -n "$helper" ] && [ -n "$line_b64" ] \
        || stop "Founderizer's answer is not one this line understands. Update the hub."
    [ "$program" = "$PROGRAM" ] || stop "This hub puts the place helper in $program and this line puts it in \
$PROGRAM. Copy the line again from Founderizer."
    say "setting this host up for $targets, reached as $user"

    user_step "$user"
    helper_step "$sha"
    account=$(getent passwd "$user") || stop "The user $user is not on this host."
    home=$(printf '%s' "$account" | cut -d: -f6)
    uid=$(printf '%s' "$account" | cut -d: -f3)
    gid=$(printf '%s' "$account" | cut -d: -f4)
    [ -n "$home" ] && [ -d "$home" ] || stop "The user $user has no home folder on this host, so it has no \
authorized_keys file."
    was=$(python3 "$work/keys.py" "$home/.ssh/authorized_keys" "$uid" "$gid" "$line_b64") \
        || stop "The line of $home/.ssh/authorized_keys could not be put in place."
    say "the vault's one line in $home/.ssh/authorized_keys ($was), which runs the place helper and nothing else"
    sshd_step

    key=$(host_key)
    line_sha=$(printf '%s' "$line_b64" | base64 -d | sha256sum | cut -d' ' -f1)
    done_said=$(printf '%s\n' "$code" | python3 "$work/api.py" "$HUB" "done" "host_key=$key" \
        "line_sha256=$line_sha" "program_sha256=$sha") \
        || stop "This host is set up, and Founderizer did not take its key: $done_said. Make a new line in \
Founderizer (Targets, Add server) and run it again; nothing here is done twice."
    rm -rf "$work"
    trap - EXIT
    say "done. This host's own key is pinned in Founderizer, so press Test on the target's row."
}

# The whole script is read before main runs: a command that reads standard input cannot take the rest of the script.
# main does not run while no hub answers its calls (see the top).
stop "Founderizer did not give this host its setup."
