---
displayName: 本地 CodeQL 告警定位与修复验收（中文版）
summary: codeql-local-triage 技能的中文翻译版，与 SKILL.md 内容一致、语言不同。
description: 本文件是 codeql-local-triage 技能的纯中文版，与 SKILL.md 内容一致、只是语言不同。不替你跑扫描，而是回答「这条 CodeQL 告警为什么报、改哪一行才会消失」——用变体二分给出可复现的因果结论。当你说「确认 taint 源 / 复现这个 CodeQL 告警 / 为什么 CodeQL 报这个 / 本地跑一次 CodeQL / 验证安全告警是否修好 / 这个告警是不是误报」，或需要判断某个 Code Scanning 告警是真漏洞还是误报时使用。也适用于给任意仓库做单条 CodeQL 查询的本地验收。它不做整库告警的批量判定与处置（不替代 Code Scanning suite、不替你 dismiss / 关闭告警）；预筛脚本可对你指定的文件/目录做敏感名清点，但不产出审计报告。
agent_created: true
---

# 本地 CodeQL 告警定位与修复验收

> **本文档为中文版（纯中文）。** 完整英文版作为 `SKILL.md` 与本文件并列维护——习惯英文请读那个。所有示例均为**模拟代码**，不含任何真实项目源码。

## 权限声明

本技能的能力边界一眼可见（机器可读声明见 frontmatter `permissions`）：

| 能力 | 范围 | 说明 |
|---|---|---|
| 读 | 你指定的本地源码 | 只读，**不修改**源码 |
| 写 | `<tree>/_bisect/` 或 `--workdir` 指定目录 | 不写其它位置（见「参数与产物命名」） |
| 执行 | `python3`；**可选** `codeql` | 列表传参、**不经 shell** |
| 网络 | 无 | 仅当你手动让 `codeql --download` 拉查询包时才联网 |

> 所有样例数据均为合成样本（见下方「示例与 fixture」）。本技能**不联网、不读凭据、不修改源码**；产物只写到上表目录。默认输出落在仓库内的 `<tree>/_bisect/`（建议加进 `.gitignore`），或你用 `--workdir` 指到仓库外。

> **语言 / Language.** 本技能拆分为两份并列文件：`SKILL.md`（英文，agent 实际加载的规范定义）与 `SKILL.zh.md`（中文）。两份内容完全一致。这种拆分是**有意选择**——方便中文平台用户拿到干净的纯中文阅读版。不提供 `--lang` 开关；要换语言，读另一份即可。

> **卖点：两个脚本零依赖.** `scan_sensitive_sources.py`（预筛）与 `read_sarif.py`（读 SARIF）**不装 CodeQL 也能跑**——只有 `bisect_taint.py` 建库时才需要 CodeQL CLI（~400 MB）。几秒就能试跑预审；只有想做对照实验时才装 CLI。

GitHub 的告警页面**不给数据流**（只标 sink 那一行），远端扫描要等几分钟，还不能做对照实验。本地跑单条查询 + 变体二分，十几分钟内就能给出**可复现的因果结论**。

脚本都在本技能目录下的 `scripts/`，下文的 `scripts/xxx.py` 均指这里。

> **示例与 fixture 均为刻意构造的模拟样本.** `tests/fixtures/repro/scan.py` 里的 `SECRET_PATTERNS` **不是真凭据**——它只是一组「`sk-…` / `ghp_…` 形状」的**正则 pattern 字符串**，里面**没有任何真实 token 或密钥**（free of any real credential）。它是为复现「名字命中 CodeQL 名字启发式（`maybeSecret()`）」这一**最小误报**而**故意保留**的：用途是教学与可复现验证，不是任何真实凭据的流转。两份 fixture 的 docstring 首行已显式标注「TEST FIXTURE — NOT THE SKILL IMPLEMENTATION / 测试样本，非技能实现」——`tests/` 目录是本技能的**自测与可执行样本，非主体逻辑**，扫描器若将其误读为技能主实现属误报。下游只把扫描结果落到 `--workdir` 指定的产物目录（**默认 `<tree>/_bisect`，在仓库内；显式传 `/tmp/taint_bisect` 可挪到系统临时区**），不会写出任何真实凭据。

## 适用范围与边界

本技能**不替代**整套 Code Scanning 扫描。它的定位是**单条查询的因果定位**：把一条具体告警的 source → sink 路径完整复现出来，并回答「为什么报、改哪一行才会消失」。它**不适用于**对整库做完整的安全告警排查（那是整套 Code Scanning **查询集 / query suite** 的职责，与系统服务/计划任务无关）。

**运行期依赖：**

- 三个脚本由 `python` / `python3` 执行（已在 frontmatter 声明 `metadata.openclaw.requires.bins`）。
- **CodeQL CLI 是可选依赖**：只在 `bisect_taint.py` 真正建库跑查询时需要；预筛（`scan_sensitive_sources.py`）与读 SARIF（`read_sarif.py`）两步**零依赖**，不装 CodeQL 也能跑。

**当前深耕：**

- **语言**：Python（预筛脚本 `scan_sensitive_sources.py` 只覆盖 `py/*` 查询；`read_sarif.py` 与 `bisect_taint.py` 与语言无关）。**多语言 roadmap**：Java / JavaScript / Go 的等价预筛与变体二分是后续规划，不是当前能力。
- **规则**：以 `py/clear-text-storage-sensitive-data`（CWE-312，名字启发式误报）为主战场——因为它的 source 判定**不看内容、只看名字**，最适合用变体二分证伪。

**不做的事：**

- 不做 LLM 判读或告警优先级排序——结论来自可复现的对照实验，而非模型主观判断。
- 不替代 CI：告警的最终 `state` 由 GitHub 自己的扫描决定，本技能只负责在推送前把因果查清楚。

> **步骤①的定位.** 预筛脚本 `scan_sensitive_sources.py` 是**服务单条告警定位的前置粗筛**——枚举「哪些变量名可能被 CodeQL 当 sensitive source」以缩小变体范围。它本身**不对任何告警下结论，也不产出审计报告**（只输出候选源清单，可作你关心文件/目录的清点）。把它当成「目录/整仓安全审计器」是误读。

本技能**适用于**：你手上已有一条具体 CodeQL / Code Scanning 告警，想确认它是真漏洞还是误报，或想在推送前本地验证修复是否生效。

## 权限与可用性声明

> 能力边界一览见上方「权限声明」表（机器可读声明在 frontmatter `permissions`）。本节只补**可用性降级路径**：

**可用性降级路径.** CodeQL CLI 是**可选依赖**：

- 若 CodeQL CLI 因网络或环境原因暂不可得，`scan_sensitive_sources.py`（预筛）与 `read_sarif.py`（读 SARIF）两步**仍零依赖可用**，足以完成「是否命中名字启发式」「数据流长什么样」两类判定；
- `bisect_taint.py` 不强制联网下载——可直接指向你本机已安装的 `codeql` 可执行文件（`--codeql /path/to/codeql`），无需任何额外网络配置即可跑对照实验。

换言之，**核心判定不依赖一次海外大体积下载**；CLI 只是把「可复现因果结论」从两步推进到第三步的增强项。

## 相关技能与取舍

**跨技能分工.** 本技能只做**本地因果定位**。如果你要**在 GitHub 上直接管理告警本身**（列出、改状态、批量处理 Code Scanning 告警），交给 GitHub 官方的告警管理能力（如 `github-security-codescanning-alerts-skill` 或 `gh api code-scanning`）；本技能负责在推送前把「为什么报、哪行消失」查清楚——二者互补而非竞争。

**「无 LLM 判读」是取舍，不是缺失.** 结论来自**可复现的对照实验**（变体二分 + 实测数据流），而非模型主观判断——这让结果可审计、可复核。若你确实需要**语义层判读 / 告警优先级排序**这类 LLM 能力，去看 `li-codeql-llm` 之类的技能；本技能**刻意不做**那一层。

## 0. 何时用

- 告警「看不懂为什么报」或「改了还在报」
- 需要区分**真漏洞**与**误报**（尤其名字启发式类规则）
- 修复后想在推送前**本地先证伪/证实**，而不是推上去等 CI
- 想判断「这条告警是不是我这次改动引入的」

## 1. 三条命令的总览

```bash
python scripts/scan_sensitive_sources.py <src>   # 1. 预筛，省去 9 分钟建库
python scripts/read_sarif.py <out.sarif>         # 2. 打印完整 source→sink 路径
python scripts/bisect_taint.py --source f.py --tree . \
    --variant t2=OLD:NEW --codeql <codeql>       # 3. 一次只改一个变量
```

三个脚本都带 `--help`。前两个是**零依赖**的，没装 CodeQL 也能跑。

> **退出码契约.** 三个脚本统一：`0` = 成功 / 未发现候选源；`1` = 发现候选源或基线未复现（**判定结果**，可作 CI 门禁）；`2` = 输入 / 运行错误（路径不存在、`codeql` 调用失败、超时等，需排查）。缺失路径**不会**被误判成「干净」——这是 v1.0.2 修掉的回归点。
>
> 高频问题（基线没复现怎么办 / 复杂改动怎么做变体 / 能不能直接 dismiss / 哪些名字不算敏感源）集中收口在 **`references/faq.md`**；`references/` 下每个文件的用途见 **`references/README.md`**。

### 每一步需要什么 / 需求矩阵

| 步骤 | 脚本 | 需要 CodeQL CLI? | 需要联网? | 读 | 写 |
|---|---|---|---|---|---|
| ① 预筛 | `scan_sensitive_sources.py` | **否** | 否 | 源码文件 | stdout / `--json` |
| ② 读 SARIF | `read_sarif.py` | **否** | 否 | `.sarif` | stdout / `--expect` 断言 |
| ③ 变体二分 | `bisect_taint.py` | **是**（仅建库跑查询时） | 否¹ | 源码文件 | `<tree>/_bisect`（临时库 + SARIF） |

¹ 第 ③ 步只有让 `database analyze --download` 拉查询包时才联网；指向本机 `codeql`（`--codeql /path/to/codeql`）则既不需联网也不需配 PATH。

两个零依赖步骤只要有 Python 就能跑——足以完成「是否命中名字启发式」「数据流长什么样」两类判定。完整的步步教程（排查示例、安装、验证、CI 门禁）在 **`README.md`**；本文件是给 agent 看的参考。

## 2. 安装 CodeQL CLI

一次性下载 ~400 MB（只含提取器，查询包首次 `analyze` 时自动拉）。平台包名、校验与最新版本查询的**完整步骤见 `references/running-codeql-cli.md`**。CodeQL CLI 是可选依赖——预筛与读 SARIF 不需要它。

## 3. 建库 + 跑单条查询

`codeql database create` + `codeql database analyze` 的**精确命令、耗时实测与查询路径语法见 `references/running-codeql-cli.md`**。只跑目标那一条规则，别跑整个 **query suite（查询套件，CodeQL 的查询集合概念，与系统服务/计划任务无关）**。

## 4. 读 SARIF 的 codeFlows（关键一步）

```bash
python scripts/read_sarif.py "$T/out.sarif"              # 全路径
python scripts/read_sarif.py "$T/out.sarif" --json       # 机器可读
python scripts/read_sarif.py "$T/out.sarif" --expect 0   # 断言清零，CI 友好
```

`codeFlows[].threadFlows[].locations[]` 就是 **source → … → sink** 的完整路径，含每步行号与节点语义。`results` 条数 = 0 即「干净」，这是最直接的验收信号。

> 别用 SARIF 文件大小当判断依据，也别只看 sink 行号——那是 GitHub 页面上就能看到的信息，对定位零增量。

## 5. 变体二分：定位到底是哪一步

一次只改一个变量，各自建库跑同一条查询，看告警是否消失。

> **「变体二分」≠ Trail of Bits 的 `variant-analysis`.** 我们的 **variant bisection** 是**一次只改一个变量、用对照实验定位单条告警的 taint 成因**（归因 / root-cause）；`variant-analysis` 是在多个项目里**找同一 bug 的其他实例**（普查 / sweep）。两者方向相反，别装错、也别归类错。

```bash
# 先确认改动对不对（不建库）
python scripts/bisect_taint.py --source scan.py --tree . --dry-run \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

# 完整跑：暂存 + 建库 + 分析 + 判定表
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql --workdir /tmp/taint_bisect
```

### 参数与产物命名

**写盘范围（固定约定）：**

| 项 | 值 |
|---|---|
| 默认产物目录 | `<tree>/_bisect/`（**在仓库内**；`/tmp/taint_bisect` 只是显式传 `--workdir` 时的示例值，并非默认） |
| 覆盖行为 | 每次运行 `rmtree` 清空重建（幂等），不会累积旧产物 |
| 是否改源码 | **否**（只读源码，产出另存） |
| 建议 | 把 `_bisect/` 加进 `.gitignore`；或 `--workdir` 指到仓库外（如 `/tmp/taint_bisect`） |

- `--workdir <dir>`（可选）：变体目录与产物的落地目录。**不给时默认 `<--tree>/_bisect`**（包根下的 `_bisect/`，已被拷贝时的 ignore 列表排除，不会污染待查仓库）；示例常显式传 `/tmp/taint_bisect` 把它放到系统临时区。
  **覆盖行为**：每次运行会**清空并重建**各变体目录（含其中的 `_db`），所以重复运行是幂等的、不会累积旧产物。
- `--codeql <path>`（可选）：指向本机已安装的 `codeql` 可执行文件。**不给则只生成变体、不跑查询**（退出码 0，并打印等价建库/分析命令模板），方便先 `--dry-run` 核对改动对不对。
- 产物命名规则：
  - 变体目录：`workdir/<NAME>/`（如 `workdir/t1_control/`、`workdir/t2_rename/`）
  - 每变体数据库：`workdir/<NAME>/_db`
  - 每变体 SARIF：`workdir/<NAME>.sarif`（**与变体目录同级、同名加 `.sarif` 后缀**，不在目录内）
  - 判定表：直接打印到 stdout，不落盘

复杂改动（正则手术）做不了字面量替换时，手工产出一份改好的文件再整份替换：`--variant-file t3=/tmp/t3.py`。

| 变体 | 含义 | 结果解读 |
| --- | --- | --- |
| `t1_control`（自动添加） | 原样 | **必须复现**；不复现说明本地与远端不一致，结论全部不可信（脚本会 exit 1） |
| `t2_xxx` | 去掉嫌疑 A | 0 处 ⇒ A 是成因 |
| `t3_xxx` | 去掉嫌疑 B | 仍命中 ⇒ B **不是**成因 |

> 教训：**读 QL 源码推断成因很容易错**. 首选假设猜错是常态——路径上的 `base64` 解码、`json.dumps`、f-string 都看着像污染源，直到你用变体去测。**先做对照实验，再下结论.**

## 6. 名字启发式类规则（Python 安全查询最常见的误报源）

`py/clear-text-storage-sensitive-data` 等规则的 source **不看内容、只看名字**.

**速查表见 `references/sensitive-data-heuristics.md`**（5 组正则、反向排除器、7 类 source、CWE-312 的 source/sink 特例）。最需要记住的三条：

1. `maybeSecret()` = `(?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*`
   — 变量名里含 `secret` 子串就够，前面的词不构成豁免（除非正好是 `is` / `is_`）。
2. **`"[REDACTED_SECRET]"` 这类占位符不会判敏感**（`notSensitiveRegexp` 里有 `redact`）。
   所以「把字段脱敏」是有效修复，**别把占位符当污染源去查**。
3. CWE-312 只把 `secret` / `password` / `private` 当 source，**`id` 与 `certificate` 被显式排除**；
   sink 是「写入文件的数据」。

**所以：任何「名字像密钥的变量」只要流向「写文件/写日志」sink 就会触发.**
修法通常是**改名**（逻辑零变更），不需要抑制注释、更不该 dismiss。

## 7. 修复后验收清单

1. 预筛：该文件的 source 数归零
2. 功能回归：改的是名字，**被测工具本身行为必须不变**（跑 fixture，含退出码语义）
3. 变体/整仓真 CodeQL：目标查询 **0 处**
4. 源码注释写清「**勿改回去**」+ 规则出处——否则下一个人会好心帮你还原
5. 推上去后**关单由 GitHub 自己的扫描做**：等 CodeQL workflow 跑完再看告警是否 closed。
   不要用 `--jq .updated_at` 判断是否重扫（该字段只在状态变化时刷新）；
   判断依据只能是 `state` 或位置行号是否变。

## 8. 移植 QL 正则到 Python re 的两个坑

预筛脚本做的是「等价移植」，改它的时候会遇到：

1. QL 支持**变长 lookbehind**：`(?<!is|is_)` 在 Python 抛 `PatternError: look-behind requires fixed-width pattern`；
   等价改写为**多个定长断言串联**：`(?<!is)(?<!is_)`（须同时通过才排除）。
2. **内联 `(?is)` 不能出现在表达式中间**（`global flags not at the start of the expression`）。
   把 flags 作为参数传给 `re.compile(pattern, re.I | re.S)`；
   同一正则有多个分支且 flag 不同时，拆成多条 pattern 分别编译再取并集。

改动后跑 `python scripts/scan_sensitive_sources.py --self-test` 验证分类器仍与 QL 定义一致。

## 9. 常见坑汇总

- 告警位置行号会随改动漂移；`most_recent_instance.location` 才反映最近一次扫描
- CMake/编译型语言建库要跑构建；**Python 不需要**
- 整仓建库前确认工作区没有**并发改动**；用 `ls --time-style=full-iso` 对 mtime 与建库时间做时序核对
- 变体要**只改一处**；若两份 fixture/变体除目标变量外还有别的差异，对照实验就失效了
  （`tests/run_tests.py` 里有一项断言专门守这件事）
- `git archive HEAD` 只读 **HEAD 树里的** `.gitattributes`；文件未跟踪时 `export-ignore` 静默失效。
  自检：前者须无输出，后者须返回 `export-ignore: set`

## 10. 延伸阅读

- **`references/README.md`** — `references/` 目录索引：每个文件的用途与适用场景一览。
- **`references/faq.md`** — 高频问题集中收口：基线未复现、复杂改动怎么做变体、能否直接 dismiss、哪些名字不算敏感源。
- **`references/running-codeql-cli.md`** — 安装 / 验证 CodeQL CLI 的完整步骤链（第 ③ 步 `bisect_taint.py` 需要它）。
- **`references/sensitive-data-heuristics.md`** — 名字启发式规则原理速查（正向 7 类 source + 反向排除器）。
