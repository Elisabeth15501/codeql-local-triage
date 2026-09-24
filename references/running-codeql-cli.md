# 安装 CodeQL CLI 与建库跑查询 / Installing the CodeQL CLI & building a database

> 本文件承接 `SKILL.md` 中「环境搭建」类细节，让 `SKILL.md` 只保留触发与主流程。
> This file holds the environment-setup detail so `SKILL.md` stays focused on triggers and the main flow.

CodeQL CLI 是**可选依赖**：预筛（`scan_sensitive_sources.py`）与读 SARIF（`read_sarif.py`）两步零依赖即可用；只有在 `bisect_taint.py` 真正建库跑查询时才需要它。
The CodeQL CLI is an **optional dependency**: the prefilter and SARIF reader need it for nothing; only `bisect_taint.py` (build + analyse) uses it.

---

## 1. Installing the CodeQL CLI / 安装 CodeQL CLI

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

---

## 2. Build a database + run a single query / 建库 + 跑单条查询

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
