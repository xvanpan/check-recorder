#!/usr/bin/env python3
"""recorder.py —— 没有 check 脚本时，用"录制 / 重放"代替行为基线。

两个用途：
  1. 录一段交互（喂什么、期待什么、回显了什么），存成 golden.json；
  2. 加固后用同一段交互重放，比对回显是否一致 —— 这就是一份最小 check。

并且它可以直接当 hardener 的 --check 用：
    python3 recorder.py record --elf ./pwn --cwd run --steps s.json --out golden.json
    python3 hardener.py --auto --elf ./pwn \
        --check "python3 recorder.py replay --elf ./pwn --cwd run --golden golden.json" ...

用法
----
录制（二选一）：
    --stdin-file script.txt          # 整段 stdin 一次性喂进去（行驱动菜单够用）
    --steps steps.json               # 有状态交互：等某段回显再发
回放：
    --golden golden.json [--norm hex|none]

steps.json 格式（每项可只写一半）：
    [
      {"expect": "Choice: ", "send": "1\\n"},
      {"expect": "size: ",   "send": "48\\n"},
      {"expect": "Choice: ", "send": "5\\n", "timeout": 2}
    ]
二进制发送用 "send_hex": "00ff10"（与 send 二选一）。

归一化
------
--norm hex（默认）：把 0x 开头的十六进制、以及 >=8 位连续 hex 串替换成 <HEX>，
                    这样 PIE/libc 泄漏、堆地址变化不会造成假失败；
--norm none：字节完全一致才 PASS（加固不改代码路径时应当成立）。

退出码：0 = PASS，1 = FAIL，2 = 用法/IO 错误。
"""
import argparse
import base64
import hashlib
import json
import os
import re
import select
import subprocess
import sys
import time

HEX_RE = re.compile(rb'0x[0-9a-fA-F]{2,}')
BARE_HEX_RE = re.compile(rb'\b[0-9a-fA-F]{8,}\b')


BIN_RE = re.compile(rb'[^\x20-\x7e]+')
NUM_RE = re.compile(rb'\b\d{4,}\b')


PRINTABLE = set(range(0x20, 0x7f)) | {0x09}


def guess_masks(data, limit=8):
    """从输出里自动找"上一行像提示、下一行是乱码"的位置，生成 mask_after 标记。"""
    lines = data.split(b'\n')
    toks = []
    for i, ln in enumerate(lines):
        if i == 0 or not ln:
            continue
        if not any(b not in PRINTABLE and b != 0x0a for b in ln):
            continue
        prev = lines[i - 1].strip()
        if not prev:
            continue
        tok = prev.decode('latin1')
        if len(tok) > 40:
            tok = tok[-40:]
        if tok not in toks:
            toks.append(tok)
        if len(toks) >= limit:
            break
    return toks


def normalize(data, mode, mask_after=()):
    if mode != 'none':
        data = HEX_RE.sub(b'<HEX>', data)
        data = BARE_HEX_RE.sub(b'<HEX>', data)
        if mode == 'bin':                 # 连不可打印字节一起抹（泄露出来的原始内存）
            data = BIN_RE.sub(b'<BIN>', data)
        if mode in ('num', 'all'):        # pid / 计数 / 时间这类长数字
            data = NUM_RE.sub(b'<N>', data)
        if mode == 'all':
            data = BIN_RE.sub(b'<BIN>', data)
    if mask_after:
        # 出现某个标记（例如 "PICK 32"）之后的那一行整行掩掉：那是随机泄漏
        lines = data.split(b'\n')
        out = []
        hit = False
        for ln in lines:
            if hit:
                out.append(b'<LEAK>')
                hit = False
            else:
                out.append(ln)
            if any(tok.encode() in ln for tok in mask_after):
                hit = True
        data = b'\n'.join(out)
    return data


def load_steps(path):
    with open(path, encoding='utf-8') as fp:
        return json.load(fp)


def run_steps(argv, cwd, steps, timeout, env=None):
    """按 steps 驱动，返回 (stdout_bytes, exit_code, killed)。"""
    p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         env=env)
    out = bytearray()

    def drain(tmo):
        deadline = time.time() + tmo
        while True:
            left = deadline - time.time()
            if left <= 0:
                return
            r, _, _ = select.select([p.stdout], [], [], left)
            if not r:
                return
            chunk = os.read(p.stdout.fileno(), 8192)
            if not chunk:
                return
            out.extend(chunk)

    for st in steps:
        exp = st.get('expect')
        if isinstance(exp, str):
            exp = exp.encode()
        if exp:
            dl = time.time() + st.get('timeout', timeout)
            while exp not in bytes(out) and time.time() < dl and p.poll() is None:
                drain(0.05)
        if 'send' in st:
            p.stdin.write(st['send'].encode())
            p.stdin.flush()
        elif 'send_hex' in st:
            p.stdin.write(bytes.fromhex(st['send_hex']))
            p.stdin.flush()

    # 收尾：把剩下的输出读干净，最多等 timeout
    dl = time.time() + timeout
    while p.poll() is None and time.time() < dl:
        drain(0.1)
    killed = False
    if p.poll() is None:
        p.kill()
        killed = True
    try:
        drain(0.2)
    except Exception:                                  # noqa: BLE001
        pass
    rc = p.wait()
    return bytes(out), rc, killed


def elf_sha(path):
    try:
        return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except OSError:
        return None


def last_line(chunk):
    """取一段输出里最后一行的可见部分，作为"下一步该等什么"的 expect。"""
    text = chunk.rstrip()
    if not text:
        return None
    line = text.split(b'\n')[-1]
    if len(line.strip()) < 3:                 # 太短（空行/单字符）不作为 expect
        return None
    return line.decode('latin1')


def invalidate_golden(steps_path):
    """steps 更新后，顺手把旁边的 golden.json 改名，避免下次用过期基线。"""
    d = os.path.dirname(os.path.abspath(steps_path)) or '.'
    g = os.path.join(d, 'golden.json')
    if os.path.exists(g):
        try:
            os.replace(g, g + '.bak')
            print('注意: 已把旧的 golden.json 改名为 golden.json.bak（steps 变了）')
        except OSError:
            pass


def cmd_learn(a):
    """交互式录制：你敲一行、回车，它就记一步（expect 从这步之前的输出里抓）。

    要求 stdin 能按行读（终端、管道、script 都行）；子进程挂在 pty 上，
    这样它的提示会立刻出现，也不会因为没 flush 卡住。
    """
    import pty
    argv = ['./' + os.path.basename(a.elf)] if a.argv is None else a.argv
    master, slave = pty.openpty()
    p = subprocess.Popen(argv, cwd=a.cwd, stdin=slave, stdout=slave,
                         stderr=slave, close_fds=True)
    os.close(slave)
    buf = bytearray()
    steps = []

    def drain(tmo=0.25):
        deadline = time.time() + tmo
        while True:
            left = deadline - time.time()
            if left <= 0:
                return
            r, _, _ = select.select([master], [], [], left)
            if not r:
                return
            try:
                data = os.read(master, 4096)
            except OSError:
                return
            if not data:
                return
            os.write(sys.stdout.fileno(), data)
            buf.extend(data)

    sys.stderr.write('# 照提示输入，回车记一步；Ctrl-D 结束并写 %s\n' % a.out)
    drain(0.8)                                  # banner + 第一个提示
    for line in sys.stdin:
        line = line.rstrip('\n')
        if not line.strip() and not a.allow_empty:
            continue                       # 空行（误触回车）不记，否则回放必挂
        step = {}
        exp = last_line(bytes(buf))
        if exp and a.with_expect:
            step['expect'] = exp
        step['send'] = line + '\n'
        step['timeout'] = a.step_timeout
        steps.append(step)
        buf.clear()
        try:
            os.write(master, line.encode() + b'\n')
        except OSError:
            break
        drain(a.step_timeout)
        if p.poll() is not None:
            break
    try:
        p.kill()
    except Exception:                                # noqa: BLE001
        pass
    with open(a.out, 'w', encoding='utf-8') as fp:
        json.dump(steps, fp, ensure_ascii=False, indent=2)
    invalidate_golden(a.out)
    sys.stderr.write('\n# 记了 %d 步 -> %s\n' % (len(steps), a.out))
    return 0


def cmd_steps(a):
    """只给"依次要输入什么"，自动生成 steps.json（expect 从实际输出里抓）。"""
    inputs = [x for x in a.inputs.replace('\\n', '\n').split(',')]
    argv = ['./' + os.path.basename(a.elf)] if a.argv is None else a.argv
    p = subprocess.Popen(argv, cwd=a.cwd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    buf = bytearray()

    def drain(tmo):
        deadline = time.time() + tmo
        while True:
            left = deadline - time.time()
            if left <= 0:
                return bytes(buf)
            r, _, _ = select.select([p.stdout], [], [], left)
            if not r:
                return bytes(buf)
            chunk = os.read(p.stdout.fileno(), 8192)
            if not chunk:
                return bytes(buf)
            buf.extend(chunk)

    drain(a.timeout)                           # 先吃 banner + 第一个提示
    steps = []
    for idx, item in enumerate(inputs):
        exp = last_line(bytes(buf))
        step = {}
        if exp and a.with_expect:
            step['expect'] = exp
        if a.hex:
            step['send_hex'] = item.encode().hex()
        else:
            step['send'] = item + '\n'
        step['timeout'] = a.step_timeout
        steps.append(step)
        buf.clear()
        try:
            p.stdin.write(item.encode() + (b'' if a.hex else b'\n'))
            p.stdin.flush()
        except Exception:                      # noqa: BLE001
            print('[!] 第 %d 步发送失败（进程已结束？）' % (idx + 1))
            break
        drain(a.step_timeout + 0.2)

    try:
        p.kill()
    except Exception:                          # noqa: BLE001
        pass
    with open(a.out, 'w', encoding='utf-8') as fp:
        json.dump(steps, fp, ensure_ascii=False, indent=2)
    invalidate_golden(a.out)
    print(json.dumps(steps, ensure_ascii=False, indent=2))
    print('\n-> %s（%d 步；用 ep.sh rec 录制，或用 --with-expect 0 只发不等）'
          % (a.out, len(steps)))
    return 0


def cmd_record(a):
    if a.steps:
        steps = load_steps(a.steps)
        blob = None
    elif a.stdin_file or a.stdin is not None:
        blob = (open(a.stdin_file, 'rb').read() if a.stdin_file
                else a.stdin.encode())
        steps = [{'send_hex': blob.hex()}]
    else:
        blob = b''
        steps = []
    argv = ['./' + os.path.basename(a.elf)] if a.argv is None else a.argv
    out, rc, killed = run_steps(argv, a.cwd, steps, a.timeout)
    masks = list(getattr(a, 'mask_after', []) or [])
    if not masks:
        masks = guess_masks(out)
        if masks:
            print('record: 自动掩掉随机泄漏行: %s' % masks)
    golden = {
        'elf_sha256': elf_sha(os.path.join(a.cwd, argv[0])),
        'cwd': os.path.abspath(a.cwd),
        'argv': argv,
        'steps': steps,
        'trace_len': len(out),
        'trace_sha256': hashlib.sha256(out).hexdigest(),
        'stdout_b64': base64.b64encode(out).decode(),
        'exit': rc,
        'killed': killed,
        'norm': a.norm,
        'mask_after': masks,
        'recorded_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    with open(a.out, 'w', encoding='utf-8') as fp:
        json.dump(golden, fp, ensure_ascii=False, indent=2)
    print('record: %d 字节, exit=%s%s -> %s'
          % (len(out), rc, ' (killed)' if killed else '', a.out))
    return 0


def cmd_replay(a):
    with open(a.golden, encoding='utf-8') as fp:
        g = json.load(fp)
    argv = ['./' + os.path.basename(a.elf)] if a.argv is None else a.argv
    out, rc, killed = run_steps(argv, a.cwd, g['steps'], a.timeout)
    masks = tuple(a.mask_after or g.get('mask_after') or ())
    want = normalize(base64.b64decode(g['stdout_b64']), a.norm, masks)
    got = normalize(out, a.norm, masks)
    fail = []
    if got != want:
        fail.append('输出不一致（%d vs %d 字节）' % (len(got), len(want)))
        i = 0
        while i < min(len(got), len(want)) and got[i] == want[i]:
            i += 1
        lo = max(0, i - 30)
        fail.append('第一处不一致 @%d: 期望 %r / 实际 %r'
                    % (i, want[lo:i + 20], got[lo:i + 20]))
    if a.strict_exit and rc != g['exit']:
        fail.append('退出码 %r != %r' % (rc, g['exit']))
    if killed and not g.get('killed'):
        fail.append('进程没自己退出（被超时杀掉）')
    if a.verbose or fail:
        print('--- 期望(%d) ---' % len(want))
        print(want[:a.lines].decode('latin1', 'replace'))
        print('--- 实际(%d) ---' % len(got))
        print(got[:a.lines].decode('latin1', 'replace'))
    if fail:
        print('REPLAY FAIL: ' + '; '.join(fail))
        return 1
    print('REPLAY PASS  (%d 字节一致, exit=%s)' % (len(got), rc))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('learn', help='交互式：你敲一步，它记一步')
    s.add_argument('--elf', required=True)
    s.add_argument('--cwd', default='.')
    s.add_argument('--argv', nargs='*', default=None)
    s.add_argument('--out', '-o', default='steps.json')
    s.add_argument('--step-timeout', type=float, default=0.6)
    s.add_argument('--with-expect', type=int, default=1)
    s.add_argument('--allow-empty', action='store_true',
                   help='把空行也记成一步（默认跳过）')
    s.add_argument('--lines', type=int, default=400)

    s = sub.add_parser('steps', help='只给"依次输入什么"，自动生成 steps.json')
    s.add_argument('--elf', required=True)
    s.add_argument('--cwd', default='.')
    s.add_argument('--argv', nargs='*', default=None)
    s.add_argument('--inputs', required=True,
                   help='依次输入的内容，逗号分隔，例如 "1,48,5"（\\n 可转义）')
    s.add_argument('--out', '-o', default='steps.json')
    s.add_argument('--timeout', type=float, default=1.2,
                   help='首次等待 banner 的时间')
    s.add_argument('--step-timeout', type=float, default=0.6)
    s.add_argument('--with-expect', type=int, default=1,
                   help='0 = 不生成 expect（只按顺序发）')
    s.add_argument('--hex', action='store_true', help='二进制输入（inputs 当文本转 hex）')
    s.add_argument('--lines', type=int, default=400)

    for name in ('record', 'replay'):
        s = sub.add_parser(name)
        s.add_argument('--elf', required=True, help='要跑的二进制（相对或绝对）')
        s.add_argument('--cwd', default='.', help='工作目录（含 ld/libc/flag）')
        s.add_argument('--argv', nargs='*', default=None,
                       help='覆盖 argv（默认 ./<elf 名>）')
        s.add_argument('--timeout', type=float, default=5.0)
        s.add_argument('--norm', choices=('hex', 'bin', 'num', 'all', 'none'), default='hex',
                       help='hex=屏蔽地址; bin=再屏蔽不可打印字节（有 PICK/leak 的录制用这个）')
        s.add_argument('--lines', type=int, default=400,
                       help='失败时最多打印多少行')
        if name == 'record':
            s.add_argument('--out', '-o', required=True, help='golden.json 输出路径')
            s.add_argument('--steps', help='有状态交互脚本（json）')
            s.add_argument('--stdin-file', help='整段 stdin 从文件读')
            s.add_argument('--stdin', help='整段 stdin 直接给')
            s.add_argument('--mask-after', action='append', default=[],
                           help='记录到 golden 里：出现该标记后的那一行整行掩掉')
        else:
            s.add_argument('--golden', '-g', required=True)
            s.add_argument('--strict-exit', action='store_true',
                           help='退出码也必须一致')
            s.add_argument('--verbose', action='store_true')
            s.add_argument('--mask-after', action='append', default=[],
                           help='出现该标记后的那一行整行掩掉（随机泄漏，可重复给）')
    a = ap.parse_args(argv)
    try:
        if a.cmd == 'record':
            return cmd_record(a)
        if a.cmd == 'steps':
            return cmd_steps(a)
        if a.cmd == 'learn':
            return cmd_learn(a)
        return cmd_replay(a)
    except FileNotFoundError as exc:
        print('找不到文件: %s' % exc)
        print('提示：目标若是动态链接（PT_INTERP 指向 ./ld-x.so），'
              '除了二进制外还要把 ld-*.so 和 libc 一起放进 --cwd')
        return 2


if __name__ == '__main__':
    sys.exit(main())
