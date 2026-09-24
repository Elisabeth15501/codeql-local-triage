#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read a CodeQL SARIF file and print the **source -> ... -> sink** path of every alert.

读 CodeQL 的 SARIF，把告警的 **source -> ... -> sink 完整路径** 打出来。

Why you need it / 为什么需要它
------------------------------
GitHub's alert page **gives you no data flow** — it shows the sink line and nothing about where the
taint came from. The output of ``codeql database analyze --format=sarif-latest`` contains
``runs[].results[].codeFlows[].threadFlows[].locations[]``, which *is* the complete path. When you
are asking "why does this fire?", this step is usually where the answer is.

GitHub 的告警页面**不给数据流**——只告诉你 sink 在哪一行，不告诉你污染是从哪来的。
而 ``codeql database analyze --format=sarif-latest`` 的产物里有
``runs[].results[].codeFlows[].threadFlows[].locations[]``，那才是完整路径。
排查「为什么报这个」时，这一步通常是答案所在。

Usage / 用法
------------
    python read_sarif.py out.sarif                 # full path / 完整路径
    python read_sarif.py out.sarif --paths-only    # sink locations only / 只列 sink 位置
    python read_sarif.py out.sarif --json          # machine-readable / 机器可读
    python read_sarif.py out.sarif --expect 0      # assert the result count (CI) / 断言结果条数

Exit codes / 退出码：0 = zero results (or ``--expect`` matched) / 无结果或断言通过；
1 = results present or assertion failed / 有结果或断言失败。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _snippet(region: dict) -> str:
    txt = (region.get("snippet") or {}).get("text", "")
    return " ".join(txt.split())[:100]


def _clean_message(text: str) -> str:
    """CodeQL 的 SARIF message 会把同一句重复一遍（带 (1) 链接标注），去掉相邻重复行。"""
    lines, out = [ln.strip() for ln in text.splitlines() if ln.strip()], []
    for ln in lines:
        if not out or out[-1] != ln:
            out.append(ln)
    return " ".join(out)


def _loc_desc(loc: dict) -> dict:
    """把 SARIF 的一层 location 压成扁平描述。"""
    pl = loc.get("physicalLocation", {})
    reg = pl.get("region", {}) or {}
    return {
        "file": pl.get("artifactLocation", {}).get("uri", "?"),
        "line": reg.get("startLine"),
        "endLine": reg.get("endLine"),
        "col": reg.get("startColumn"),
        "role": (loc.get("message") or {}).get("text", ""),
        "snippet": _snippet(reg),
    }


def parse_sarif(path: Path) -> dict:
    """返回 {tool, version, artifacts, results:[{rule, level, message, sink, flows:[[step,...]]}]}"""
    data = json.loads(path.read_text(encoding="utf-8"))
    runs = data.get("runs", [])
    out = {"file": str(path), "tool": "?", "version": "?", "artifacts": 0, "results": []}
    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        out["tool"] = driver.get("name", "?")
        # 版本在 semanticVersion（CodeQL 不填 version 字段）
        out["version"] = driver.get("semanticVersion") or driver.get("version") or "?"
        # result 级 level 常缺省，回退到 rules[].defaultConfiguration.level
        level_by_rule = {r.get("id"): (r.get("defaultConfiguration") or {}).get("level")
                         for r in driver.get("rules", []) or []}
        out["artifacts"] += len(run.get("artifacts", []) or [])
        for r in run.get("results", []) or []:
            rule_id = r.get("ruleId", "?")
            sink = None
            for loc in r.get("locations", []) or []:
                sink = _loc_desc(loc)
                break
            flows = []
            for cf in r.get("codeFlows", []) or []:
                for tf in cf.get("threadFlows", []) or []:
                    steps = [_loc_desc(lf["location"]) for lf in tf.get("locations", []) or []]
                    if steps:
                        flows.append(steps)
            out["results"].append({
                "rule": rule_id,
                "level": r.get("level") or level_by_rule.get(rule_id) or "?",
                "message": _clean_message((r.get("message") or {}).get("text", "")),
                "sink": sink,
                "flows": flows,
            })
    return out


def print_report(info: dict, paths_only: bool = False) -> None:
    print("=" * 78)
    print(f"SARIF: {info['file']}")
    print(f"工具: {info['tool']} {info['version']}   扫描文件数: {info['artifacts']}")
    print("=" * 78)
    n = len(info["results"])
    print(f"\n★ 结果数: {n}  -> {'✅ 干净' if not n else '⛔ 有告警'}\n")
    for i, r in enumerate(info["results"], 1):
        sink = r["sink"] or {}
        print(f"[{i}] {r['rule']}  ({r['level']})")
        if r["message"]:
            print(f"    {r['message']}")
        print(f"    sink: {sink.get('file')}:{sink.get('line')}")
        if paths_only:
            continue
        for fi, steps in enumerate(r["flows"], 1):
            print(f"    ── taint 路径 #{fi}（source → … → sink，共 {len(steps)} 步）──")
            for si, s in enumerate(steps):
                tag = "SOURCE" if si == 0 else ("SINK  " if si == len(steps) - 1 else "      ")
                print(f"      {tag} {si:2d}. {s['file']}:{s['line']:<5} {s['role']}")
                if s["snippet"]:
                    print(f"                  | {s['snippet']}")
        print()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Parse a CodeQL SARIF file and print source->sink data flows. / "
                    "解析 CodeQL SARIF，打印 source→sink 数据流。")
    ap.add_argument("sarif", nargs="+",
                    help="SARIF file(s), one or more / SARIF 文件（可多个）")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON, English keys / 输出机器可读 JSON（英文 key）")
    ap.add_argument("--paths-only", action="store_true",
                    help="list sink locations only, do not expand the flow / 只列 sink 位置，不展开数据流")
    ap.add_argument("--expect", type=int, metavar="N",
                    help="assert the total result count is N; exit 1 otherwise / "
                         "断言结果总条数为 N；不符则退出码 1")
    args = ap.parse_args(argv)

    infos = []
    for raw in args.sarif:
        p = Path(raw)
        if not p.is_file():
            print(f"[error] 文件不存在: {p}", file=sys.stderr)
            return 2
        try:
            infos.append(parse_sarif(p))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"[error] 解析失败 {p}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2

    total = sum(len(i["results"]) for i in infos)

    if args.json:
        print(json.dumps({"sarifs": infos, "total_results": total},
                         ensure_ascii=False, indent=2))
    else:
        for info in infos:
            print_report(info, paths_only=args.paths_only)
        if len(infos) > 1:
            print(f"合计: {len(infos)} 份 SARIF / {total} 条结果")

    if args.expect is not None:
        if total != args.expect:
            print(f"❌ 断言失败：期望 {args.expect} 条结果，实际 {total} 条", file=sys.stderr)
            return 1
        print(f"✅ 断言通过：结果数 = {args.expect}")
        return 0
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
