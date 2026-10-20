# check-recorder

交互式录制一个程序的"运行痕迹"，生成可重放的 golden 基线 —— 相当于**没有 check 脚本时，现场造一份 check**。

用途：给服务端二进制做行为回归（加固、重构、热更新前后比对），或者只是确认"改了没事"。

```
你敲一步  →  它记一步  →  steps.json
                    ↓
        record  →  golden.json（含完整 stdout + 退出码）
                    ↓
        replay  →  同一段交互再跑一遍，逐字节比对
```

## 安装

无依赖，只要 Python 3.8+（纯标准库，不需要 pwntools）：

```bash
git clone <this-repo> && cd check-recorder
chmod +x recorder.py
```

## 30 秒上手

```bash
# 1) 交互式录制：按程序提示输入，Ctrl-D 结束
./recorder.py learn --elf ./pwn --cwd . --out steps.json

# 2) 录成基线
./recorder.py record --elf ./pwn --cwd . --steps steps.json --out golden.json

# 3) 重放比对（原版自己必须 PASS）
./recorder.py replay --elf ./pwn --cwd . --golden golden.json
```


## 录制模式

| 模式 | 适合 | 命令 |
|---|---|---|
| `learn` | 有人值守，边敲边记 | `recorder.py learn --elf ./pwn -o steps.json` |
| `steps` | 已知输入序列，批量生成 | `recorder.py steps --elf ./pwn --inputs "1,48,5"` |
| `record --stdin-file` | 整段输入一次性喂（行驱动菜单） | `recorder.py record --elf ./pwn --stdin-file in.bin -o g.json` |

`learn` 结束时会把记到的步骤打出来，空行会显式标注 `<空行`。

## steps.json

```json
[
  {"expect": "Choice: ", "send": "1\n",  "timeout": 0.6},
  {"expect": "size: ",   "send": "48\n", "timeout": 0.6},
  {"expect": "Choice: ", "send": "5\n",  "timeout": 0.6}
]
```

- `expect`：等到这段字节出现再发（不写就直接发）。
- `send`：要发的文本；二进制用 `"send_hex": "00ff10"`。
- 只写一半也行 —— 只有 `send` 就是"按顺序发、不等"。

## golden.json

```json
{
  "elf_sha256": "…", "cwd": "/abs/path", "argv": ["./pwn"],
  "steps": [...],
  "stdout_b64": "…", "trace_sha256": "…", "trace_len": 1553,
  "exit": 0, "killed": false,
  "mask_after": ["PICK 32"],
  "norm": "hex", "recorded_at": "2026-10-18T13:00:00Z"
}
```

`stdout` 原样存 base64，比对时两边做同样的归一化。

## 归一化（避免随机量造成假失败）

| `--norm` | 抹掉什么 | 适用 |
|---|---|---|
| `hex`（默认） | `0x…`、≥8 位连续 hex | 地址泄漏、PIE/libc |
| `bin` | 再加不可打印字节 | 直接 dump 内存 |
| `num` | 再加 ≥4 位数字 | pid、计数、耗时 |
| `all` | 以上全部 | 最宽松 |
| `none` | 不抹，逐字节严格 | 真正的字节级回归 |

`record` 还会**自动检测**"上一行像提示、下一行是乱码"的位置，把标记写进 `mask_after`，
重放时整行掩成 `<LEAK>`：

```
record: 自动掩掉随机泄漏行: ['PICK 32', 'BOARD 2']
```

也可以手工给：

```bash
./recorder.py record … --mask-after "PICK 32" --mask-after "BOARD 2"
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | PASS |
| 1 | FAIL（打印期望/实际，并指出第一处不一致的偏移） |
| 2 | 用法/文件错误（例如目标缺 loader） |

失败时会输出：

```
REPLAY FAIL: 输出不一致（338 vs 338 字节）; 第一处不一致 @280: 期望 b'…' / 实际 b'…'
```

## 常见问题

**`找不到文件: './pwn'`**
二进制是动态链接、`PT_INTERP` 指向 `./ld-2.31.so` 之类的相对路径，`--cwd` 里要同时放 loader 和 libc。

**录制到的步骤回放就失败**
先 `replay` 原版自己（同一份 golden），若也失败说明录制与真实交互不同步：多半是随机泄漏没掩，加 `--norm bin` 或 `--mask-after`。

**`learn` 需要 TTY 吗**
不需要。stdin 能按行读即可（终端、管道、`script` 都行）；子进程挂在 pty 上，所以提示会实时出现。

**空行要不要记**
默认记（保证覆盖），`--skip-empty` 丢弃。

## 作为 CI 的一环

```bash
./recorder.py replay --elf ./build/pwn --cwd ./build --golden tests/golden.json \
  || { echo "behavior changed"; exit 1; }
```

## License

MIT
