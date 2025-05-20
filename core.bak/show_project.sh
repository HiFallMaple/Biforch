#!/usr/bin/env bash
#
# show_project.sh
#
# 1. Print a filtered tree of the repo
# 2. Dump each file’s content with line-numbers
# ---------------------------------------------------------------------------

set -euo pipefail

IGNORE="__pycache__|.pytest_cache|venv|*.db|*.sqlite|htmlcov|pytest.ini|show_project.sh|reset.py|setup.py|.log|poetry.lock|.git|.coverage"

echo "============================== PROJECT TREE =============================="
tree -aI "$IGNORE"
echo

echo "============================ FILE CONTENTS =============================="

# -------- collect “regular files only” into the FILES array ---------------
# mapfile guarantees FILES is populated even when pipefail is on
mapfile -t FILES < <(
  tree -afi -I "$IGNORE" |
    grep -vE '/$'           # drop directory entries
)

# ------------------------------- dump --------------------------------------
for file in "${FILES[@]}"; do
  [[ -f $file ]] || continue   # safety guard

  echo "------------------------------ ${file#./} ------------------------------"
  nl -ba "$file" | sed 's/^/  /'
  echo
done

echo "============================== DONE =============================="
