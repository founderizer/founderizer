#!/bin/sh
# Put this Fleet checkout on the configuration ref, and create that ref the first time.
#
# The fleet keeps its configuration (team.json, profiles/, knowledge/) on the branch "config" and its code on
# "main". The hub commits the owner's changes to "config" and nothing else writes it, so a developer's push to
# "main" can no longer refuse an owner write with 409. Code reaches the fleet when a deployment merges "main"
# into "config".
#
#   sh config-ref.sh --check [<checkout>]    say what it would do, change nothing
#   sh config-ref.sh [<checkout>]            do it
#
# The first run creates "config" at origin/main's commit, so the tree does not change, no history is lost and no
# machine turns "behind": every checkout stays at the commit it had. Later runs only move a checkout onto the ref,
# which each helper also does by itself before a task session (lifecycle.follow_config_ref).
set -e

CONFIG_BRANCH=config
CODE_BRANCH=main
check=no
kit=""

for arg in "$@"; do
    case "$arg" in
        --check) check=yes ;;
        -*) echo "config-ref.sh: unknown option $arg" >&2; exit 2 ;;
        *) kit="$arg" ;;
    esac
done
[ -n "$kit" ] || kit=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$kit"

say() { echo "config-ref: $*"; }
stop() { echo "config-ref: $*" >&2; exit 1; }
act() {
    if [ "$check" = yes ]; then
        say "would run: git $*"
    else
        git "$@"
    fi
}

git rev-parse --git-dir >/dev/null 2>&1 || stop "$kit is not a git checkout"
[ -z "$(git status --porcelain --untracked-files=no)" ] || stop "the checkout has its own changes; commit or push them first"
git fetch -q origin || stop "could not fetch origin"

head=$(git rev-parse HEAD)
branch=$(git symbolic-ref --short --quiet HEAD || echo "")

if git rev-parse --verify --quiet "refs/remotes/origin/$CONFIG_BRANCH" >/dev/null; then
    say "origin has $CONFIG_BRANCH at $(git rev-parse --short "origin/$CONFIG_BRANCH")"
    git merge-base --is-ancestor "$head" "origin/$CONFIG_BRANCH" ||
        stop "this checkout has commits that origin/$CONFIG_BRANCH lacks; push them to it first"
else
    [ "$check" = yes ] || [ "$branch" = "$CODE_BRANCH" ] ||
        stop "create the ref from a checkout of $CODE_BRANCH; this one is on ${branch:-no branch}"
    git rev-parse --verify --quiet "refs/remotes/origin/$CODE_BRANCH" >/dev/null ||
        stop "origin has no $CODE_BRANCH ref"
    [ "$head" = "$(git rev-parse "origin/$CODE_BRANCH")" ] ||
        stop "this checkout is not at origin/$CODE_BRANCH; the ref must start at the commit that the fleet runs"
    say "creating $CONFIG_BRANCH at $(git rev-parse --short HEAD), the commit that the fleet runs now"
    act push -q origin "HEAD:refs/heads/$CONFIG_BRANCH"
fi

# DevOps plan 0.1: the checkout moves onto the ref only where `lifecycle.py may-take` lets it.
if git rev-parse --verify --quiet "refs/remotes/origin/$CONFIG_BRANCH" >/dev/null; then
    python3 ./lifecycle.py may-take . "origin/$CONFIG_BRANCH" ||
        stop "this checkout may not move onto origin/$CONFIG_BRANCH: the line above says why"
fi

if [ "$branch" = "$CONFIG_BRANCH" ]; then
    act merge -q --ff-only "origin/$CONFIG_BRANCH"
elif git rev-parse --verify --quiet "refs/heads/$CONFIG_BRANCH" >/dev/null; then
    act checkout -q "$CONFIG_BRANCH"
    act merge -q --ff-only "origin/$CONFIG_BRANCH"
else
    act checkout -q -b "$CONFIG_BRANCH" --track "origin/$CONFIG_BRANCH"
fi

if [ "$check" = yes ]; then
    say "check only: nothing changed"
    exit 0
fi

now=$(git rev-parse HEAD)
on=$(git symbolic-ref --short --quiet HEAD || echo "")
[ "$on" = "$CONFIG_BRANCH" ] || stop "the checkout is on ${on:-no branch}, not $CONFIG_BRANCH"
[ "$now" = "$head" ] || say "the checkout moved from $(git rev-parse --short "$head") to $(git rev-parse --short "$now")"
say "on $CONFIG_BRANCH at $(git rev-parse --short HEAD); the code branch stays at $(git rev-parse --short "origin/$CODE_BRANCH")"
