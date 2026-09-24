# codeql-local-triage

**在本地复现 CodeQL 告警、用「变体二分」定位 taint 源，并在推送前验证修复。**

GitHub 的 Code Scanning 告警页面**不告诉你数据从哪来**——只标出 sink 那一行。
远端扫描又要等好几分钟，还没法做对照实验。这个仓库把排查过程变成三条命令：

```bash
python scripts/scan_sensitive_sources.py src/          # 1. 免建库预筛，先猜个方向
python scripts/read_sarif.py out.sarif                 # 2. 读 SARIF，画出 source→sink 全路径
python scripts/bisect_taint.py --source f.py --tree . \
    --variant t2=OLD:NEW --codeql <codeql>             # 3. 一次只改一个变量，建库跑查询，看告警是否消失
```

---

## 一个真实案例：把「误报」查到根上

某项目在 GitHub 上报了一条 **error 级** `py/clear-text-storage-sensitive-data`：

```
scripts/compliance_check.py:205  This expression stores sensitive data as clear text.
```

该文件是个合规检查工具，**从不存任何凭据**。第 205 行是它自己把检查结果写成 JSON：

```python
Path(args.json).write_text(json.dumps({...}))
```

看起来像误报，但「感觉像误报」不能作为 dismiss 的理由。本地跑一次 CodeQL，从 SARIF 的
`codeFlows` 里取出完整路径：

```
SOURCE  0. compliance_check.py:78    ControlFlowNode for List
        1. compliance_check.py:78    ControlFlowNode for SECRET_PATTERNS
        2. compliance_check.py:126   ControlFlowNode for SECRET_PATTERNS
        3. compliance_check.py:126   ControlFlowNode for why
        4. compliance_check.py:131   ControlFlowNode for Fstring
        8. compliance_check.py:156   ControlFlowNode for scan_text()
       11. compliance_check.py:157   ControlFlowNode for why
       16. compliance_check.py:206   ControlFlowNode for Dict
SINK   17. compliance_check.py:205   ControlFlowNode for Attribute()
```

**污染源是变量名 `SECRET_PATTERNS`**——那只是个存放正则字符串的列表，里面没有任何凭据。
CodeQL 的名字启发式（`maybeSecret()`）只看名字含不含 `secret`。

### 但结论不能靠推理，要靠对照实验

一次只改一个变量，各自建库跑同一条查询（`scripts/bisect_taint.py` 就是干这个的）：

| 变体 | 改了什么 | 结果数 | 判定 |
| --- | --- | --- | --- |
| `t1_control` | 原样 | 1 | 基线复现 ✅ |
| `t2_rename` | `SECRET_PATTERNS` → `CREDENTIAL_PATTERNS` | **0** | ✅ 就是这个名字 |
| `t3_nodecode` | 去掉 base64 解码 | 1 | ⛔ base64 无关 |
| `t4_nosnippet` | 把写入内容换成常量 | 1 | ⛔ 内容无关 |

我最初的推断是「taint 源是 base64 解码」——**t3 直接把它证伪了**。这就是为什么必须做对照实验，
而不是读一遍 QL 源码就下结论。

修法：**改名，逻辑零变更**。

```diff
-SECRET_PATTERNS = [...]
+CREDENTIAL_PATTERNS = [...]
```

整仓复验（52 个文件）：告警 **0 处**。

---

## 仓库内容

| 文件 | 作用 |
| --- | --- |
| `scripts/scan_sensitive_sources.py` | **免建库预筛**。把 CodeQL 的名字启发式对等移植成 Python `ast` 检查，静态列出所有可能成为 taint 源的名字/字面量。省掉一次 ~9 分钟的整仓建库。 |
| `scripts/read_sarif.py` | **读 SARIF 的 codeFlows**，把 source→sink 全路径按步打印。这一步通常是答案所在。支持 `--expect N` 做断言。 |
| `scripts/bisect_taint.py` | **变体二分**。生成「只改一处」的源码副本 → 逐个建库 + 分析 → 输出判定表。基线没复现会直接报错，避免采信无效结论。 |
| `references/sensitive-data-heuristics.md` | 名字启发式速查表：5 组正则、反向排除器、7 类 source、CWE-312 的 source/sink 特例。 |
| `SKILL.md` | 给 AI agent（Claude Code / WorkBuddy 等）用的技能定义，可整套安装。 |
| `tests/` | 不需要 CodeQL 的自测：两份**实测** SARIF fixture + 逐项断言。 |

## 快速开始

### 0. 安装 CodeQL CLI（一次性，约 15 分钟）

从 [github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries/releases) 取对应平台的包：

```bash
gh release download v2.27.1 --repo github/codeql-cli-binaries --pattern "codeql-win64.zip"
python -c "import zipfile; zipfile.ZipFile('codeql-win64.zip').extractall('.')"
./codeql/codeql version
```

> 该 zip **只含提取器**，查询包（`codeql/python-queries`）会在 `database analyze --download`
> 时自动拉取。下载 400MB 左右，建议后台跑。大文件用 Python `zipfile` 解压比 `unzip` 稳。

只要 `scan_sensitive_sources.py` 和 `read_sarif.py` 的话，**不装 CodeQL 也能用**（自测就跑得起来）。

### 1. 预筛

```bash
python scripts/scan_sensitive_sources.py src/            # 目录会递归
python scripts/scan_sensitive_sources.py $(git ls-files '*.py')
python scripts/scan_sensitive_sources.py src/ --json     # 机器可读
```

退出码：`0` 干净 / `1` 发现候选源 —— 可以直接当 CI 门禁。

### 2. 跑单条查询

只跑目标那一条，别跑整个 suite（`python-code-scanning.qls` 要几十分钟）：

```bash
codeql database create  /tmp/db --language=python --source-root=src --overwrite --threads=0
codeql database analyze /tmp/db --download --format=sarif-latest --output=/tmp/out.sarif \
    --threads=0 "codeql/python-queries:Security/CWE-312/CleartextStorage.ql"
```

### 3. 读数据流

```bash
python scripts/read_sarif.py /tmp/out.sarif
python scripts/read_sarif.py /tmp/out.sarif --json
python scripts/read_sarif.py /tmp/out.sarif --expect 0    # 断言告警清零，CI 可用
```

### 4. 变体二分

```bash
# 先只看改动对不对（不建库）
python scripts/bisect_taint.py --source scan.py --tree . --dry-run \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

# 完整跑
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql --workdir /tmp/taint_bisect
```

复杂改动（正则手术那种）做不了字面量替换时，手工产出一份改好的文件再整份替换：

```bash
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant-file t3_nodecode=/tmp/t3_scan.py --codeql /path/to/codeql
```

## 验证

```bash
python tests/run_tests.py        # 或 pytest tests/ -q
```

不需要装 CodeQL。它用仓库内两份**实测 SARIF**（`tests/fixtures/sarif/`）做断言，覆盖：

- 预筛正则自检（分类器与 QL 定义一致）
- `repro/scan.py` 命中 1 处候选源、`repro_fixed/scan.py` 干净 —— 且两份文件**除变量名外逐字节相同**（保证对照实验只有一个变量）
- `read_sarif` 判读 1 条 / 0 条正确，`--expect` 断言生效
- 能从 `codeFlows` 取回 source 行，且比对回源文件确认就是那行敏感名赋值

`tests/fixtures/repro/` 是一个 **25 行、不含任何凭据**的最小复现，同样触发 error 级告警。

## 目录结构

```
.
├── scripts/
│   ├── scan_sensitive_sources.py   预筛（无依赖）
│   ├── read_sarif.py               数据流读取（无依赖）
│   └── bisect_taint.py             变体二分（需 CodeQL）
├── references/
│   └── sensitive-data-heuristics.md
├── tests/
│   ├── run_tests.py
│   └── fixtures/
│       ├── README.md               夹具说明与重新生成方法
│       ├── repro/scan.py           命中（25 行最小复现）
│       ├── repro_fixed/scan.py     对照（只改了变量名）
│       └── sarif/                  两份实测 SARIF
├── SKILL.md
└── LICENSE
```

## 适用范围与限制（说清楚免得误用）

- **只处理名字启发式这一类误报。** 真漏洞（凭据真的被明文写盘）当然要改代码，不是改名。
  先看 `read_sarif.py` 打出的路径里源是什么，再决定。
- **预筛脚本目前只支持 Python**（`py/*` 查询）。`read_sarif.py` 与 `bisect_taint.py` 是语言无关的。
- **正则抄的是特定版本的 CodeQL。** 实测基线是 CodeQL CLI 2.27.1 / `codeql/python-queries` 1.8.11。
  上游更新后 `references/` 与 `scan_sensitive_sources.py` 需要同步——请以你本地的
  `SensitiveDataHeuristics.qll` 为准。
- **本项目的定位是「本地预验 + 定位」，不是替代 CI。** 告警的最终状态仍由 GitHub 自己的扫描决定。
  注意 `code-scanning/alerts/<n>` 的 `updated_at` **只在状态变化时才刷新**，
  不能用它判断「有没有重扫」；要看 `state` 或行号是否变了。
- 本地与远端结论不一致时，先确认本地建库时工作区没有**并发改动**
  （另一个会话正在改文件会让你的结论对不上）。

## 署名

`references/sensitive-data-heuristics.md` 与 `scripts/scan_sensitive_sources.py` 中的正则、
QL 片段取自 [github/codeql](https://github.com/github/codeql)（MIT License，Copyright GitHub, Inc.），
本项目是对这些定义的**可读重述与等价移植**，非 GitHub 官方产物。

本项目以 [MIT License](LICENSE) 发布。
