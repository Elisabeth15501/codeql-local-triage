#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变体二分：一次只改一个变量，逐个建库跑同一条查询，用「告警是否消失」定位 taint 源。

为什么不用「读 QL 源码推断」
---------------------------
QL 的 source 定义可能有好几处候选，靠读源码猜出「是哪一处」很容易错
（本项目就发生过：先推断是 base64 解码，实验证明真因是变量名）。
一次只改一个变量、各自建库跑同一条查询，能在十几分钟内给出**可复现的因果结论**。

变体约定
--------
  t1_control   原样复制（自动添加）—— 必须复现告警，否则本地环境与远端不一致，结论不可信
  t2_xxx       去掉嫌疑 A  —— 0 处 ⇒ A 是成因
  t3_xxx       去掉嫌疑 B  —— 仍命中 ⇒ B 不是成因

用法
----
    # 只生成变体目录，不跑 CodeQL（先看看改对了没）
    python bisect_taint.py --source scan.py --tree . --dry-run \
        --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

    # 完整跑：生成 + 建库 + 分析 + 出判定表
    python bisect_taint.py --source scan.py --tree . \
        --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
        --codeql C:/path/to/codeql.exe \
        --workdir C:/Temp/taint_bisect

    # 复杂改动（正则手术那种）：手工做一份改好的文件，整份替换进去
    python bisect_taint.py --source scan.py --tree . --variant-file t3_nodecode=/tmp/t3.py ...

退出码：0 = 跑完且基线复现成功；1 = 基线未复现（结论不可信）；2 = 运行出错。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_sarif import parse_sarif  # noqa: E402

CONTROL = "t1_control"
DEFAULT_QUERY = "codeql/python-queries:Security/CWE-312/CleartextStorage.ql"


def _run(cmd: list[str]) -> int:
    print("  $ " + " ".join(f'"{c}"' if " " in c else c for c in cmd), flush=True)
    return subprocess.call(cmd)


def _stage(tree: Path, src_rel: Path, dst: Path, body: str | None,
           workdir: Path | None = None) -> Path:
    """把 tree 复制到 dst，可选地把 src_rel 的内容替换为 body。返回变体内的源码路径。

    注意：默认 workdir 可能就落在 tree 里面（``<tree>/_bisect``）。若不在复制时排除它，
    第 2 个变体会把第 1 个变体的 ``_db`` 一并拷进来，逐轮膨胀。
    """
    if dst.exists():
        shutil.rmtree(dst)

    def _ignore(cur: str, names: list[str]) -> set[str]:
        skip = {"_db", "__pycache__", "_bisect", ".git", ".codeql"}
        return {n for n in names if n in skip}

    shutil.copytree(tree, dst, ignore=_ignore)
    target = dst / src_rel
    if body is not None:
        # newline="" 双向关闭换行翻译：读进来的 \r\n / \n 原样写回，
        # 使变体文件与源文件**除替换处外逐字节一致**（这是「只改一处」的前提）。
        # 注意 Windows 上 write_text 默认会把 \n 写成 CRLF，那会让变体多出一处差异。
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
    return target


def read_raw(path: Path) -> str:
    """按原样读取（保留 \\r\\n），配合 _stage 的 newline="" 实现字节保真。"""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="变体二分定位 CodeQL taint 源。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 = 跑完且基线复现；1 = 基线未复现；2 = 出错。")
    ap.add_argument("--source", required=True, help="要改的源文件（相对 --tree）")
    ap.add_argument("--tree", default=".", help="包根目录，整体复制进每个变体（默认当前目录）")
    ap.add_argument("--variant", action="append", default=[], metavar="NAME=OLD:NEW",
                    help="字面量替换（可重复）。注意 OLD:NEW 用冒号分隔，NEW 里可含冒号")
    ap.add_argument("--variant-file", action="append", default=[], metavar="NAME=PATH",
                    help="整份替换源文件（可重复，用于正则手术类复杂改动）")
    ap.add_argument("--workdir", default=None, help="变体与产物的落地目录")
    ap.add_argument("--codeql", default=None, help="codeql 可执行文件；不给则只生成变体")
    ap.add_argument("--query", default=DEFAULT_QUERY, help=f"查询（默认 {DEFAULT_QUERY}）")
    ap.add_argument("--language", default="python", help="database create 的 --language")
    ap.add_argument("--dry-run", action="store_true", help="只生成变体，不跑 CodeQL")
    args = ap.parse_args(argv)

    tree = Path(args.tree).resolve()
    src_rel = Path(args.source)
    src_abs = (tree / src_rel).resolve()
    if not src_abs.is_file():
        print(f"[error] 源文件不存在: {src_abs}", file=sys.stderr)
        return 2
    workdir = Path(args.workdir or (tree / "_bisect")).resolve()

    # ── 组装变体清单：control 恒在最前 ──────────────────────────────────────
    variants: list[tuple[str, str | None]] = [(CONTROL, None)]
    for spec in args.variant:
        if "=" not in spec or ":" not in spec.split("=", 1)[1]:
            ap.error(f"--variant 需要 NAME=OLD:NEW 格式，收到: {spec}")
        name, pair = spec.split("=", 1)
        old, new = pair.split(":", 1)
        text = read_raw(src_abs)
        mutated = text.replace(old, new)
        if mutated == text:
            print(f"[error] 变体 {name} 未产生任何改动（OLD 没出现？）: {old!r}", file=sys.stderr)
            return 2
        variants.append((name, mutated))
        print(f"变体 {name}: {text.count(old)} 处 {old!r} -> {new!r}")
    for spec in args.variant_file:
        name, _, path = spec.partition("=")
        p = Path(path)
        if not p.is_file():
            print(f"[error] 替换文件不存在: {p}", file=sys.stderr)
            return 2
        variants.append((name, read_raw(p)))
        print(f"变体 {name}: 整份替换为 {p}")

    # ── 生成变体目录 ────────────────────────────────────────────────────────
    print(f"\n工作目录: {workdir}\n包根: {tree}\n源文件: {src_rel}\n")
    staged: list[tuple[str, Path]] = []
    for name, body in variants:
        d = workdir / name
        tgt = _stage(tree, src_rel, d, body, workdir)
        n_lines = len(tgt.read_text(encoding="utf-8").splitlines())
        staged.append((name, d))
        print(f"  已生成 {name:14s} ({n_lines} 行) -> {tgt}")

    if args.dry_run or not args.codeql:
        print("\n（未跑 CodeQL。加 --codeql <path> 执行建库+分析。）")
        print("等价命令模板：")
        print(f'  "{args.codeql or "<codeql>"}" database create "<变体目录>/_db" '
              f'--language={args.language} --source-root="<变体目录>" --overwrite --threads=0')
        print(f'  "{args.codeql or "<codeql>"}" database analyze "<变体目录>/_db" '
              f'--format=sarif-latest --output="<变体目录>.sarif" --threads=0 "{args.query}"')
        return 0

    if not Path(args.codeql).is_file():
        print(f"[error] codeql 不存在: {args.codeql}", file=sys.stderr)
        return 2

    # ── 逐个建库 + 分析 ─────────────────────────────────────────────────────
    counts: dict[str, int] = {}
    for name, d in staged:
        print(f"\n════ {name} ════")
        db = d / "_db"
        sarif = workdir / f"{name}.sarif"
        rc = _run([args.codeql, "database", "create", str(db),
                   f"--language={args.language}", f"--source-root={d}",
                   "--overwrite", "--threads=0"])
        if rc:
            print(f"[error] {name} 建库失败（exit {rc}）", file=sys.stderr)
            return 2
        rc = _run([args.codeql, "database", "analyze", str(db),
                   "--format=sarif-latest", f"--output={sarif}",
                   "--threads=0", args.query])
        if rc:
            print(f"[error] {name} 分析失败（exit {rc}）", file=sys.stderr)
            return 2
        try:
            counts[name] = len(parse_sarif(sarif)["results"])
        except Exception as exc:  # noqa: BLE001 - 报告并继续，别让一个变体毁掉整轮
            print(f"[warn] {name} 的 SARIF 解析失败: {type(exc).__name__}: {exc}", file=sys.stderr)
            counts[name] = -1

    # ── 判定表 ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print(f"{'变体':16s} {'结果数':>7s}   判定")
    print("-" * 78)
    for name, _ in staged:
        n = counts.get(name, -1)
        if name == CONTROL:
            verdict = "基线复现 ✅" if n > 0 else "⛔ 基线未复现！结论不可信"
        elif n == 0:
            verdict = "✅ 告警消失 ⇒ 该改动就是 taint 源"
        elif n > 0:
            verdict = "⛔ 仍命中 ⇒ 该改动不是成因"
        else:
            verdict = "? 解析失败"
        print(f"{name:16s} {n:>7d}   {verdict}")

    if counts.get(CONTROL, 0) <= 0:
        print("\n⚠️  基线没有复现告警：本地环境/查询与远端可能不一致，"
              "上面其它变体的结论不能采信。")
        return 1
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
