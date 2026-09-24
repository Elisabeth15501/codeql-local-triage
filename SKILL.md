---
name: codeql-local-triage
description: 在本地复现 GitHub Code Scanning（CodeQL）告警、用「变体二分」定位 taint 源并验证修复。当用户说「确认 taint 源 / 复现这个 CodeQL 告警 / 为什么 CodeQL 报这个 / 本地跑一次 CodeQL / 验证安全告警是否修好 / 这个告警是不是误报」，或需要判断某个 Code Scanning 告警是真漏洞还是误报时使用。也适用于给任意仓库做单条 CodeQL 查询的本地验收。Reproduce CodeQL / Code Scanning alerts locally, locate the taint source by variant bisection, and verify a fix before pushing — use this when asked to confirm a taint source, to triage whether an alert is a false positive, or to validate a security alert fix locally. 关键词／keywords：CodeQL、Code Scanning、taint source、数据流、SARIF、codeFlows、误报、false positive、py/clear-text-storage-sensitive-data、CWE-312。
agent_created: true
---

# 本地 CodeQL 告警定位与修复验收
# Local CodeQL alert triage and fix verification

> **文档为中英对照：英文在前、中文在后，讲的是同一件事。**
> **This document is bilingual: English first, 中文 follows. Both cover the same content.**
> 所有示例均为**模拟代码**，不含任何真实项目源码。
> **All examples are synthetic sample code**; no real project source is included.

GitHub's alert page **gives you no data flow** (it only marks the sink), remote scans take minutes, and
you cannot run a controlled experiment there. Running a single query locally plus variant bisection
gives you a **reproducible causal conclusion** in about ten minutes.

GitHub 的告警页面**不给数据流**（只标 sink 那一行），远端扫描要等几分钟，还不能做对照实验。
本地跑单条查询 + 变体二分，十几分钟内就能给出**可复现的因果结论**。

All scripts live in `scripts/` inside this skill directory; `scripts/xxx.py` below refers to them.
脚本都在本技能目录下的 `scripts/`，下文的 `scripts/xxx.py` 均指这里。

## 0. When to use / 何时用

- An alert "makes no sense" or "still fires after I fixed it"
  告警「看不懂为什么报」或「改了还在报」
- You must tell a **real vulnerability** from a **false positive** (especially name-heuristic rules)
  需要区分**真漏洞**与**误报**（尤其名字启发式类规则）
- You want to prove/disprove a fix locally before pushing, instead of waiting for CI
  修复后想在推送前**本地先证伪/证实**，而不是推上去等 CI
- You need to know whether this alert was introduced by *your* change
  想判断「这条告警是不是我这次改动引入的」

## 1. The three commands / 三条命令的总览

```bash
python scripts/scan_sensitive_sources.py <src>   # 1. prefilter, saves a 9-min DB build / 免建库预筛
python scripts/read_sarif.py <out.sarif>         # 2. print the full source→sink path / 打印数据流
python scripts/bisect_taint.py --source f.py --tree . \
    --variant t2=OLD:NEW --codeql <codeql>       # 3. change one thing at a time / 一次只改一个变量
```

All three have `--help`. `scan_sensitive_sources.py` and `read_sarif.py` are **zero-dependency** and
run without CodeQL.

三个脚本都带 `--help`。前两个是**零依赖**的，没装 CodeQL 也能跑。

## 2. Installing the CodeQL CLI / 安装 CodeQL CLI

One-off, ~400 MB. The zip contains **extractors only**; query packs are pulled during
`database analyze`.

一次性，下载 ~400MB。该 zip **只含提取器**，查询包在 `database analyze` 时自动拉，不用单独下。

```bash
gh release download v2.27.1 --repo github/codeql-cli-binaries --pattern "codeql-win64.zip"
python -c "import zipfile; zipfile.ZipFile('codeql-win64.zip').extractall('.')"
./codeql/codeql version          # expect 2.27.1 / 应打印 2.27.1
```

- Patterns: `codeql-win64.zip` / `codeql-linux64.zip` / `codeql-osx64.zip` / `codeql-osx-arm64.zip`
  对应平台：Windows x64 / Linux x64 / macOS Intel / Apple silicon
- Validate first with `zipfile.ZipFile(...).testzip()`; Python's `zipfile` is more reliable than `unzip`
  先 `testzip()` 校验；用 Python `zipfile` 比 `unzip` 稳
- Latest version: `gh api repos/github/codeql-cli-binaries/releases/latest --jq .tag_name`
  查最新版本用这条命令
- In practice the download is slow (~15 min) — run it in the background
  实测下载很慢（约 15 分钟），放后台跑

## 3. Build a database + run a single query / 建库 + 跑单条查询

**Run only the rule you care about** — never the whole suite (`python-code-scanning.qls` takes tens of
minutes).

**只跑目标那一条**，别跑整个 suite（`python-code-scanning.qls` 要几十分钟）。

```bash
codeql database create  "$T/db" --language=python --source-root="$SRC" --overwrite --threads=0
codeql database analyze "$T/db" --download --format=sarif-latest \
    --output="$T/out.sarif" --threads=0 \
    "codeql/python-queries:Security/CWE-312/CleartextStorage.ql"
```

- `--download` installs `codeql/python-queries` into `~/.codeql/packages` on first use
  首次会装 `codeql/python-queries` 到 `~/.codeql/packages`
- Measured cost: single-file DB ~70 s; a whole mid-sized Python repo ~9 min (TRAP import dominates);
  single-query evaluation ~30 s
  耗时实测：单文件建库 ~70s；整仓建库 ~9 分钟（TRAP import 占大头）；单查询求值 ~30s
- Query path syntax is `<pack>:<path inside pack>`. Find paths with GitHub search:
  查询路径规则 `<pack>:<pack 内相对路径>`。找路径用 GitHub 搜索：
  `gh api "search/code?q=repo:github/codeql+<rule-id>+in:file" --jq '.items[].path'`

## 4. Read `codeFlows` from the SARIF (the key step) / 读 SARIF 的 codeFlows（关键一步）

```bash
python scripts/read_sarif.py "$T/out.sarif"              # full path / 全路径
python scripts/read_sarif.py "$T/out.sarif" --json       # machine-readable / 机器可读
python scripts/read_sarif.py "$T/out.sarif" --expect 0   # assert zero, CI-friendly / 断言清零
```

`codeFlows[].threadFlows[].locations[]` **is** the complete source → … → sink path, with the line
number and node semantics of every step. `results` count = 0 means "clean" — the most direct
acceptance signal there is.

`codeFlows[].threadFlows[].locations[]` 就是 **source → … → sink** 的完整路径，含每步行号与节点语义。
`results` 条数 = 0 即「干净」，这是最直接的验收信号。

> Do not use the SARIF file size, and do not stop at the sink line — that is information you already
> had on the GitHub page, and it adds nothing.
>
> 别用 SARIF 文件大小当判断依据，也别只看 sink 行号——那是 GitHub 页面上就能看到的信息，对定位零增量。

## 5. Variant bisection: find out which step is responsible / 变体二分：定位到底是哪一步

Change exactly one thing at a time, rebuild each variant, rerun the same query, and see whether the
alert disappears.

一次只改一个变量，各自建库跑同一条查询，看告警是否消失。

```bash
# Inspect the change without building anything / 先确认改动对不对（不建库）
python scripts/bisect_taint.py --source scan.py --tree . --dry-run \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

# Full run: stage + build + analyse + verdict table / 完整跑
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql --workdir /tmp/taint_bisect
```

When a change is too complex for a literal replacement (regex surgery), produce the edited file by
hand and swap the whole file in: `--variant-file t3=/tmp/t3.py`.

复杂改动（正则手术）做不了字面量替换时，手工产出一份改好的文件再整份替换：`--variant-file t3=/tmp/t3.py`。

| Variant / 变体 | Meaning / 含义 | How to read it / 结果解读 |
| --- | --- | --- |
| `t1_control` (added automatically / 自动添加) | unchanged / 原样 | **must reproduce**; if it does not, local and remote disagree and every conclusion is invalid (the script exits 1)<br>**必须复现**；不复现说明本地与远端不一致，结论全部不可信（脚本会 exit 1） |
| `t2_xxx` | suspect A removed / 去掉嫌疑 A | 0 results ⇒ A is the cause<br>0 处 ⇒ A 是成因 |
| `t3_xxx` | suspect B removed / 去掉嫌疑 B | still fires ⇒ B is **not** the cause<br>仍命中 ⇒ B **不是**成因 |

> Lesson: reading the QL source and *inferring* the cause is unreliable. Guessing wrong on the first
> hypothesis is normal — a `base64` decode, a `json.dumps` or an f-string on the path all look like
> plausible sources until you test them. **Run the controlled experiment before you write down the
> conclusion.**
>
> 教训：**读 QL 源码推断成因很容易错**。首选假设猜错是常态——路径上的 `base64` 解码、`json.dumps`、
> f-string 都看着像污染源，直到你用变体去测。**先做对照实验，再下结论。**

## 6. Name-heuristic rules (the most common false-positive source in Python security queries)
## 6. 名字启发式类规则（Python 安全查询最常见的误报源）

Rules such as `py/clear-text-storage-sensitive-data` pick their source **by name, never by content**.

`py/clear-text-storage-sensitive-data` 等规则的 source **不看内容、只看名字**。

**Cheat sheet: `references/sensitive-data-heuristics.md`** (5 regex groups, the exclusion regex,
7 source categories, the source/sink special cases of CWE-312). The three things to remember:

**速查表见 `references/sensitive-data-heuristics.md`**（5 组正则、反向排除器、7 类 source、
CWE-312 的 source/sink 特例）。最需要记住的三条：

1. `maybeSecret()` = `(?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*`
   — a `secret` substring anywhere in the name is enough; the word in front of it grants no exemption
   (unless it is exactly `is` / `is_`).
   变量名里含 `secret` 子串就够，前面的词不构成豁免（除非正好是 `is` / `is_`）。
2. **`"[REDACTED_SECRET]"`-style placeholders are not sensitive** (the exclusion regex contains
   `redact`). So redacting a field is a valid fix — **do not go hunting for placeholders as sources**.
   **`"[REDACTED_SECRET]"` 这类占位符不会判敏感**（`notSensitiveRegexp` 里有 `redact`）。
   所以「把字段脱敏」是有效修复，**别把占位符当污染源去查**。
3. CWE-312 only treats `secret` / `password` / `private` as sources; **`id` and `certificate` are
   explicitly excluded** (`CleartextStorageCustomizations.qll`). The sink is "data written to a file"
   (`FileSystemWriteAccess.getADataNode()`).
   CWE-312 只把 `secret` / `password` / `private` 当 source，**`id` 与 `certificate` 被显式排除**；
   sink 是「写入文件的数据」。

**Therefore: any variable whose name *looks like* a key, as soon as it flows into a "write file / write
log" sink, will fire.** The usual fix is a **rename** (zero behavioural change) — not a suppression
comment, and definitely not a dismissal.

**所以：任何「名字像密钥的变量」只要流向「写文件/写日志」sink 就会触发。**
修法通常是**改名**（逻辑零变更），不需要抑制注释、更不该 dismiss。

## 7. Post-fix acceptance checklist / 修复后验收清单

1. Prefilter: `scripts/scan_sensitive_sources.py <file>` drops to zero sources
   预筛：该文件的 source 数归零
2. Functional regression: only a name changed, so **the tool's behaviour must not change** (run its
   fixtures, including exit-code semantics)
   功能回归：改的是名字，**被测工具本身行为必须不变**（跑 fixture，含退出码语义）
3. Real CodeQL over the tree: the target query returns **0 results** (`read_sarif.py --expect 0`)
   变体/整仓真 CodeQL：目标查询 **0 处**
4. Leave a comment at the source saying **"do not rename this back"** plus the rule that caused it —
   otherwise the next person will helpfully revert it
   源码注释写清「**勿改回去**」+ 规则出处
5. Once pushed, **let GitHub's own scan close the alert**: wait for the CodeQL workflow and check
   whether the alert closed. Do **not** use `code-scanning/alerts/<n> --jq .updated_at` to decide
   whether a rescan happened — that field only refreshes when the state changes, so a stale timestamp
   proves nothing. The only valid signals are `state` or whether the position moved.
   推上去后**关单由 GitHub 自己的扫描做**：等 CodeQL workflow 跑完再看告警是否 closed。
   不要用 `--jq .updated_at` 判断是否重扫（该字段只在状态变化时刷新）；
   判断依据只能是 `state` 或位置行号是否变。

## 8. Two pitfalls when porting QL regexes to Python `re` / 移植 QL 正则到 Python re 的两个坑

The prefilter is an "equivalent port"; when you touch it you will hit these:

预筛脚本做的是「等价移植」，改它的时候会遇到：

1. QL supports **variable-width lookbehind**: `(?<!is|is_)` raises
   `PatternError: look-behind requires fixed-width pattern` in Python. Rewrite it as **several
   fixed-width assertions in series**: `(?<!is)(?<!is_)` (all must pass for the exclusion to apply).
   QL 支持**变长 lookbehind**：`(?<!is|is_)` 在 Python 抛
   `PatternError: look-behind requires fixed-width pattern`；
   等价改写为**多个定长断言串联**：`(?<!is)(?<!is_)`（须同时通过才排除）。
2. **An inline `(?is)` cannot appear mid-expression** (`global flags not at the start of the
   expression`). Pass the flags to `re.compile(pattern, re.I | re.S)`; when one regex has branches
   with different flags, split them into separate patterns and take the union.
   **内联 `(?is)` 不能出现在表达式中间**（`global flags not at the start of the expression`）。
   把 flags 作为参数传给 `re.compile(pattern, re.I | re.S)`；
   同一正则有多个分支且 flag 不同时，拆成多条 pattern 分别编译再取并集。

After any change, run `python scripts/scan_sensitive_sources.py --self-test` to confirm the classifier
still agrees with the QL definitions.

改动后跑 `python scripts/scan_sensitive_sources.py --self-test` 验证分类器仍与 QL 定义一致。

## 9. Common pitfalls / 常见坑汇总

- Alert line numbers drift as you edit; only `most_recent_instance.location` reflects the latest scan
  告警位置行号会随改动漂移；`most_recent_instance.location` 才反映最近一次扫描
- CMake / compiled languages need a build before `database create`; **Python does not**
  CMake/编译型语言建库要跑构建；**Python 不需要**
- Before a whole-repo build, make sure no **concurrent edits** are happening (another process writing
  files will desynchronise your conclusion). Cross-check mtime against the build time with
  `ls --time-style=full-iso`.
  整仓建库前确认工作区没有**并发改动**；用 `ls --time-style=full-iso` 对 mtime 与建库时间做时序核对
- A variant must change **exactly one thing**. If two fixture/variant copies differ in anything else,
  the experiment is void (`tests/run_tests.py` has an assertion guarding exactly this).
  变体要**只改一处**；若两份 fixture/变体除目标变量外还有别的差异，对照实验就失效了
  （`tests/run_tests.py` 里有一项断言专门守这件事）
- `git archive HEAD` only reads the `.gitattributes` **in the HEAD tree**; if the file is untracked,
  `export-ignore` silently does nothing. Verify with `git archive HEAD | tar -t | grep <path>` (expect
  no output) and `git check-attr export-ignore -- <path>` (expect `export-ignore: set`).
  `git archive HEAD` 只读 **HEAD 树里的** `.gitattributes`；文件未跟踪时 `export-ignore` 静默失效。
  自检：前者须无输出，后者须返回 `export-ignore: set`
