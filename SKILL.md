---
name: codeql-local-triage
description: 在本地复现 GitHub Code Scanning（CodeQL）告警、用「变体二分」定位 taint 源并验证修复。当用户说「确认 taint 源 / 复现这个 CodeQL 告警 / 为什么 CodeQL 报这个 / 本地跑一次 CodeQL / 验证安全告警是否修好 / 这个告警是不是误报」，或需要判断某个 Code Scanning 告警是真漏洞还是误报时使用。也适用于给任意仓库做单条 CodeQL 查询的本地验收。关键词：CodeQL、Code Scanning、taint source、数据流、SARIF、codeFlows、误报、py/clear-text-storage-sensitive-data、CWE-312。
agent_created: true
---

# 本地 CodeQL 告警定位与修复验收

GitHub 的告警页面**不给数据流**（只标 sink 那一行），远端扫描要等几分钟，还不能做对照实验。
本地跑单条查询 + 变体二分，十几分钟内就能给出**可复现的因果结论**。

脚本都在本技能目录下的 `scripts/`，下文的 `scripts/xxx.py` 均指这里。

## 0. 何时用

- 告警「看不懂为什么报」或「改了还在报」
- 需要区分**真漏洞**与**误报**（尤其名字启发式类规则）
- 修复后想在推送前**本地先证伪/证实**，而不是推上去等 CI
- 想判断「这条告警是不是我这次改动引入的」

## 1. 三条命令的总览

```bash
python scripts/scan_sensitive_sources.py <src>          # 1. 免建库预筛（省 9 分钟）
python scripts/read_sarif.py <out.sarif>                # 2. 读 SARIF，打印 source→sink 全路径
python scripts/bisect_taint.py --source f.py --tree . \
    --variant t2=OLD:NEW --codeql <codeql>              # 3. 一次只改一个变量，看告警是否消失
```

三个脚本都带 `--help`。`scan_sensitive_sources.py` 与 `read_sarif.py` 是**零依赖**的，
没装 CodeQL 也能跑。

## 2. 安装 CodeQL CLI（一次性，下载 ~400MB）

该 zip **只含提取器**，查询包在 `database analyze` 时自动拉，不用单独下。

```bash
gh release download v2.27.1 --repo github/codeql-cli-binaries --pattern "codeql-win64.zip"
python -c "import zipfile; zipfile.ZipFile('codeql-win64.zip').extractall('.')"
./codeql/codeql version          # 应打印 2.27.1
```

- 先 `zipfile.ZipFile(...).testzip()` 校验再解压；用 Python `zipfile` 比 `unzip` 稳
- 查最新版本：`gh api repos/github/codeql-cli-binaries/releases/latest --jq .tag_name`
- 实测下载很慢（约 15 分钟），放后台跑

## 3. 建库 + 跑单条查询

**只跑目标那一条**，别跑整个 suite（`python-code-scanning.qls` 要几十分钟）。

```bash
codeql database create  "$T/db" --language=python --source-root="$SRC" --overwrite --threads=0
codeql database analyze "$T/db" --download --format=sarif-latest \
    --output="$T/out.sarif" --threads=0 \
    "codeql/python-queries:Security/CWE-312/CleartextStorage.ql"
```

- `--download` 首次会装 `codeql/python-queries` 到 `~/.codeql/packages`
- 耗时实测：单文件建库 ~70s；**整仓 52 文件建库 ~9 分钟**（TRAP import 占大头）；单查询求值 ~30s
- 查询路径规则 `<pack>:<pack 内相对路径>`。找路径用 GitHub 搜索：
  `gh api "search/code?q=repo:github/codeql+<规则id>+in:file" --jq '.items[].path'`

## 4. 读 SARIF 的 codeFlows（关键一步）

```bash
python scripts/read_sarif.py "$T/out.sarif"              # 全路径
python scripts/read_sarif.py "$T/out.sarif" --json       # 机器可读
python scripts/read_sarif.py "$T/out.sarif" --expect 0   # 断言清零，CI 可用
```

`codeFlows[].threadFlows[].locations[]` 就是 **source → … → sink** 的完整路径，含每步行号与节点语义。
`results` 条数 = 0 即「干净」，这是最直接的验收信号。

> 别用 SARIF 文件大小当判断依据，也别只看 sink 行号——那是 GitHub 页面上就能看到的信息，
> 对定位没有增量。

## 5. 变体二分：定位到底是哪一步

一次只改一个变量，各自建库跑同一条查询，看告警是否消失。

```bash
# 先确认改动对不对（不建库）
python scripts/bisect_taint.py --source scan.py --tree . --dry-run \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

# 完整跑：生成 + 建库 + 分析 + 判定表
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql --workdir /tmp/taint_bisect
```

复杂改动（正则手术）做不了字面量替换时，手工产出一份改好的文件再整份替换：
`--variant-file t3=/tmp/t3.py`。

| 变体 | 含义 | 结果解读 |
| --- | --- | --- |
| `t1_control`（自动添加） | 原样 | **必须复现**；不复现说明本地与远端不一致，结论全部不可信（脚本会 exit 1） |
| `t2_xxx` | 去掉嫌疑 A | 0 处 ⇒ A 是成因 |
| `t3_xxx` | 去掉嫌疑 B | 仍命中 ⇒ B **不是**成因 |

> 教训：本项目有一次先「读 QL 源码推断成因是 base64 解码」，对照实验证明**完全猜错**——
> 真因是变量名。**先做对照实验，再下结论。**

## 6. 名字启发式类规则（Python 安全查询最常见的误报源）

`py/clear-text-storage-sensitive-data` 等规则的 source **不看内容、只看名字**。

**速查表见 `references/sensitive-data-heuristics.md`**（5 组正则、反向排除器、7 类 source、
CWE-312 的 source/sink 特例）。最需要记住的三条：

1. `maybeSecret()` = `(?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*`
   —— 变量名里含 `secret` 子串就够，前面的词不构成豁免（除非正好是 `is` / `is_`）。
2. **`"[REDACTED_SECRET]"` 这类占位符不会判敏感**（`notSensitiveRegexp` 里有 `redact`）。
   所以「把字段脱敏」是有效修复，**别把占位符当污染源去查**。
3. CWE-312 只把 `secret` / `password` / `private` 当 source，
   **`id` 与 `certificate` 被显式排除**（`CleartextStorageCustomizations.qll`）。
   sink 是「写入文件的数据」（`FileSystemWriteAccess.getADataNode()`）。

**所以：任何「名字像密钥的变量」只要流向「写文件/写日志」sink 就会触发。**
修法通常是**改名**（逻辑零变更），不需要抑制注释、更不该 dismiss。

## 7. 修复后验收清单

1. 预筛：`scripts/scan_sensitive_sources.py <file>` 的 source 数归零
2. 功能回归：改的是名字，**被测工具本身行为必须不变**（跑 fixture，含退出码语义）
3. 变体/整仓真 CodeQL：目标查询 **0 处**（`read_sarif.py --expect 0`）
4. 源码注释写清「**勿改回去**」+ 规则出处 —— 否则下一个人会顺手把名字改回来
5. 推上去后，**关单由 GitHub 自己的扫描做**：等 CodeQL workflow 跑完再看告警是否 closed
   （不要用 `code-scanning/alerts/<n> --jq .updated_at` 判断是否重扫——
   该字段**只在状态变化时刷新**，停在旧时间不代表没重扫。判断依据只能是 `state` 或位置行号是否变）

## 8. 移植 QL 正则到 Python `re` 的两个坑

预筛脚本做的是「等价移植」，改它的时候会遇到：

1. QL 支持**变长 lookbehind**：`(?<!is|is_)` 在 Python 抛
   `PatternError: look-behind requires fixed-width pattern`。
   等价改写为**多个定长断言串联**：`(?<!is)(?<!is_)`（须同时通过才排除）。
2. **内联 `(?is)` 不能出现在表达式中间**（`global flags not at the start of the expression`）。
   把 flags 作为参数传给 `re.compile(pattern, re.I | re.S)`；
   同一正则有多个分支且 flag 不同时，拆成多条 pattern 分别编译再取并集。

改动后跑 `python scripts/scan_sensitive_sources.py --self-test` 验证分类器仍与 QL 定义一致。

## 9. 常见坑汇总

- 告警位置行号会随改动漂移；`most_recent_instance.location` 才反映最近一次扫描
- CMake/编译型语言建库要跑构建；**Python 不需要**
- 整仓建库前确认工作区没有**并发改动**（另一会话正在改文件会让你的结论对不上）；
  用 `ls --time-style=full-iso` 对 mtime 与建库时间做时序核对
- 变体要**只改一处**；若两份 fixture/变体除目标变量外还有别的差异，对照实验就失效了
  （`tests/run_tests.py` 里有一项断言专门守这件事）
- `git archive HEAD` 只读 **HEAD 树里的** `.gitattributes`；文件未跟踪时 `export-ignore` 静默失效。
  自检：`git archive HEAD | tar -t | grep <path>` 须无输出；
  `git check-attr export-ignore -- <path>` 须返回 `export-ignore: set`
