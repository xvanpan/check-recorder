#!/bin/bash
# 端到端演示：编译 demo -> 自动生成 steps -> 录 golden -> 重放
#   bash examples/demo.sh
set -eu
cd "$(dirname "$0")"
R=$(cd .. && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

gcc -O0 -o "$T/demo" demo.c
printf 'FLAG{demo}\n' > "$T/flag"

echo "== steps（只给输入序列）"
"$R/recorder.py" steps --elf demo --cwd "$T" --inputs "1,hello,2,3" -o "$T/steps.json"

echo "== record"
"$R/recorder.py" record --elf demo --cwd "$T" --steps "$T/steps.json" -o "$T/golden.json"

echo "== replay（应 PASS）"
"$R/recorder.py" replay --elf demo --cwd "$T" --golden "$T/golden.json"

echo "== 负对照（改一个字节，应 FAIL）"
python3 - "$T/golden.json" <<'PY'
import base64, json, sys
p = sys.argv[1]
g = json.load(open(p))
b = bytearray(base64.b64decode(g['stdout_b64']))
b[5] ^= 0x20
g['stdout_b64'] = base64.b64encode(bytes(b)).decode()
json.dump(g, open(p, 'w'))
PY
if "$R/recorder.py" replay --elf demo --cwd "$T" --golden "$T/golden.json" >/dev/null 2>&1; then
  echo "FAIL: 负对照没被抓到"; exit 1
else
  echo "OK: 负对照被抓住（REPLAY FAIL 符合预期）"
fi
