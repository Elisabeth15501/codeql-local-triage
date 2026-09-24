#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自测：不需要安装 CodeQL，用仓库内已存的两份实测 SARIF 做断言。

    python tests/run_tests.py        # 也兼容 pytest（函数名以 test_ 开头）

覆盖：
  1. 预筛脚本的正则自检（分类器与 QL 定义一致）
  2. repro/scan.py 命中 1 处候选源，repro_fixed/scan.py 干净
  3. 两份 fixture「除变量名外逐字节相同」——保证对照实验只有一个变量
  4. read_sarif 能正确判读两份实测 SARIF（1 条 / 0 条）与 --expect 断言
  5. read_sarif 能从 codeFlows 里取回 source 行，且就是那行敏感名赋值
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "scripts" / "scan_sensitive_sources.py"
READ = ROOT / "scripts" / "read_sarif.py"
REPRO = ROOT / "tests" / "fixtures" / "repro" / "scan.py"
REPRO_FIXED = ROOT / "tests" / "fixtures" / "repro_fixed" / "scan.py"
SARIF_HIT = ROOT / "tests" / "fixtures" / "sarif" / "repro.sarif"
SARIF_CLEAN = ROOT / "tests" / "fixtures" / "sarif" / "repro_fixed.sarif"

FAILS: list[str] = []


def _run(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), *args],
                          capture_output=True, text=True, encoding="utf-8")


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if cond else 'FAIL'}  {name}" + ("" if cond else f"    {detail}"))
    if not cond:
        FAILS.append(name)


def test_prefilter_self_test() -> None:
    r = _run(SCAN, "--self-test")
    check("预筛脚本正则自检通过", r.returncode == 0, r.stdout[-300:])


def test_repro_has_one_source() -> None:
    r = _run(SCAN, str(REPRO), "--json")
    data = json.loads(r.stdout)
    check("repro/scan.py 命中 1 处候选源", data["total_sources"] == 1,
          f"实际 {data['total_sources']}")
    srcs = data["files"][0]["sources"]
    if srcs:
        check("命中项是 SECRET_PATTERNS 的赋值",
              "SECRET_PATTERNS" in srcs[0]["label"] and srcs[0]["hits"] == ["secret"],
              json.dumps(srcs[0], ensure_ascii=False))
    check("有候选源时退出码为 1", r.returncode == 1, f"实际 {r.returncode}")


def test_fixed_is_clean() -> None:
    r = _run(SCAN, str(REPRO_FIXED), "--json")
    data = json.loads(r.stdout)
    check("repro_fixed/scan.py 无候选源", data["total_sources"] == 0,
          f"实际 {data['total_sources']}")
    check("无候选源时退出码为 0", r.returncode == 0, f"实际 {r.returncode}")


def test_fixtures_differ_only_in_name() -> None:
    """两份 fixture 必须「除这个变量名外」逐字节相同，否则对照实验混入了别的变量。

    断言方式是**严格**的：把 repro 里的这个名字全局替换掉，结果必须与 repro_fixed
    完全相等。所以两份 .py 里除代码外**不能**出现这个名字（说明文字已移到
    tests/fixtures/README.md），否则全局替换会连文档一起改掉、断言不成立。
    """
    a = REPRO.read_text(encoding="utf-8")
    b = REPRO_FIXED.read_text(encoding="utf-8")
    replaced = a.replace("SECRET_PATTERNS", "CREDENTIAL_PATTERNS")
    diff_desc = ""
    if replaced != b:
        al, bl = replaced.splitlines(), b.splitlines()
        for i, (x, y) in enumerate(zip(al, bl), 1):
            if x != y:
                diff_desc = f"首个差异在第 {i} 行: {x!r} != {y!r}"
                break
        else:
            diff_desc = f"行数不同: {len(al)} != {len(bl)}"
    check("两份 fixture 除该变量名外逐字节相同（严格替换比对）", replaced == b, diff_desc)
    # 该名字只应出现在代码里：赋值 1 处 + for 循环 1 处。若有人往 docstring 里补一句说明，
    # 全局替换就会连文档一起改掉，上面的严格比对随之失效——这项断言专门守这个。
    check("repro 中该变量名只出现在代码里（2 处）",
          a.count("SECRET_PATTERNS") == 2, f"实际出现 {a.count('SECRET_PATTERNS')} 次")


def test_read_sarif_counts() -> None:
    if not SARIF_HIT.is_file() or not SARIF_CLEAN.is_file():
        check("SARIF fixture 存在", False, "请先生成 tests/fixtures/sarif/*.sarif")
        return
    r = _run(READ, str(SARIF_HIT), "--expect", "1")
    check("repro.sarif 结果数 = 1（--expect 断言通过）", r.returncode == 0, r.stdout[-300:])
    r = _run(READ, str(SARIF_CLEAN), "--expect", "0")
    check("repro_fixed.sarif 结果数 = 0（--expect 断言通过）", r.returncode == 0, r.stdout[-300:])


def test_read_sarif_extracts_source() -> None:
    if not SARIF_HIT.is_file():
        return
    r = _run(READ, str(SARIF_HIT), "--json")
    info = json.loads(r.stdout)["sarifs"][0]
    res = info["results"][0]
    check("评到 error 级", res["level"] == "error", res["level"])
    check("规则是 py/clear-text-storage-sensitive-data",
          res["rule"] == "py/clear-text-storage-sensitive-data", res["rule"])
    check("消息指明分类为 secret", "secret" in res["message"], res["message"])
    flows = res["flows"]
    check("至少有一条 codeFlows 数据流", bool(flows), "SARIF 里没有数据流")
    if flows:
        src = flows[0][0]
        check("数据流起点落在 SECRET_PATTERNS 那一行",
              REPRO.read_text(encoding="utf-8").splitlines()[src["line"] - 1]
              .strip().startswith("SECRET_PATTERNS"),
              f"{src['file']}:{src['line']} {src['role']}")
        check("数据流终点是写文件那行",
              REPRO.read_text(encoding="utf-8").splitlines()[flows[0][-1]["line"] - 1]
              .strip().startswith("Path(out).write_text"),
              f"{flows[0][-1]['file']}:{flows[0][-1]['line']}")


TESTS = [test_prefilter_self_test, test_repro_has_one_source, test_fixed_is_clean,
         test_fixtures_differ_only_in_name, test_read_sarif_counts,
         test_read_sarif_extracts_source]


def main() -> int:
    print("=" * 70)
    print("codeql-local-triage 自测")
    print("=" * 70)
    for t in TESTS:
        print(f"\n{t.__name__}")
        t()
    print("\n" + "=" * 70)
    if FAILS:
        print(f"❌ {len(FAILS)} 项失败: {', '.join(FAILS)}")
        return 1
    print("✅ 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
