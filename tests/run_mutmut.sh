#!/bin/sh
# Mutation testing of plugins/linux/cbpf_lib.py with mutmut 3. mutmut needs the module at the top of the tree, so
# this runs on a flat copy in a temporary directory (the memory tests are left out: they need the sample).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
cp "$ROOT/plugins/linux/cbpf_lib.py" "$ROOT/plugins/linux/cbpf_syscalls.py" "$T/"
cp -R "$ROOT/tests" "$T/" && rm "$T/tests/test_memory.py"
mkdir -p "$T/sample/expected" && cp "$ROOT"/sample/expected/serial-*.log "$T/sample/expected/"
sed -i.bak 's#sys.path.insert(0, os.path.join(ROOT, "plugins", "linux"))#sys.path.insert(0, ROOT)#' "$T/tests/conftest.py"
printf '[mutmut]\nsource_paths = cbpf_lib.py\ntests_dir = tests/\nalso_copy = tests/\n    sample/\n    cbpf_syscalls.py\n' > "$T/setup.cfg"
cd "$T" && mutmut run >/dev/null 2>&1 || true
mutmut results --all true | awk '{print $NF}' | sort | uniq -c
echo "work dir: $T"
