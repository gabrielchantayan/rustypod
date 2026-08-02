#!/usr/bin/env bash
# Install the repo's git hooks. Hooks live under .git/hooks, which git does
# not version, so they have to be installed per checkout — symlink them so an
# edit here takes effect everywhere without a re-install.
#
#   tools/hooks/install.sh                  # test gate only (workstation)
#   tools/hooks/install.sh --with-autopush  # + publish-on-commit (porting VM)
set -euo pipefail

root=$(git rev-parse --show-toplevel)
hooks="$root/.git/hooks"
src="$root/tools/hooks"

link() {
  ln -sf "$src/$1" "$hooks/$1"
  chmod +x "$src/$1"
  printf '  installed %s -> tools/hooks/%s\n' "$1" "$1"
}

mkdir -p "$hooks"
link pre-commit

if [[ "${1:-}" == "--with-autopush" ]]; then
  link post-commit
else
  # Do not leave a stale autopush hook behind on a workstation.
  [[ -L "$hooks/post-commit" ]] && rm -f "$hooks/post-commit" && \
    printf '  removed post-commit (pass --with-autopush to keep it)\n'
fi

printf 'done.\n'
