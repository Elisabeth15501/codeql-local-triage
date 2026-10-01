# 安装 CodeQL CLI 与建库跑查询 / Installing the CodeQL CLI & building a database

> 本文件承接 `SKILL.md` 中「环境搭建」类细节，让 `SKILL.md` 只保留触发与主流程。
> This file holds the environment-setup detail so `SKILL.md` stays focused on triggers and the main flow.
>
> 面向完全新手的**从零完整步骤链**：下载 → 解压 → 加入 PATH → 验证 → 最小试跑 → 建库跑单条查询。
> A complete from-scratch chain for absolute beginners: download → extract → PATH → verify → minimal try-run → build & single query.

CodeQL CLI 是**可选依赖**：预筛（`scan_sensitive_sources.py`）与读 SARIF（`read_sarif.py`）两步零依赖即可用；只有在 `bisect_taint.py` 真正建库跑查询时才需要它。`bisect_taint.py` 支持 `--codeql /abs/path`，所以**不配 PATH、不联网**也能用本机已有的 `codeql`。
The CodeQL CLI is an **optional dependency**: the prefilter and SARIF reader need it for nothing; only `bisect_taint.py` (build + analyse) uses it. Because `bisect_taint.py` accepts `--codeql /abs/path`, you can run it with a local `codeql` **without touching PATH or the network**.

---

## 0. 总览 / Overview

| 阶段 | 命令 | 需要联网? | 耗时 |
|---|---|---|---|
| ① 下载 | `gh release download …` | 是（仅这一次） | ~15 min（国内见 §5） |
| ② 解压 + PATH | `zipfile.extractall` + `export PATH` | 否 | 秒级 |
| ③ 验证 | `codeql --version` / `codeql resolve languages` | 否 | 秒级 |
| ④ 最小试跑 | `codeql database create /tmp/db --language=python` | 否 | ~70 s |
| ⑤ 建库 + 跑单条查询 | `codeql database create` + `codeql database analyze --download` | 是（首次拉查询包） | 建库 ~9 min + 求值 ~30 s |

只有 ① 和 ⑤ 的 `--download` 会联网；④ 完全离线，足够验证 CLI 是否装好。
Only ① and the `--download` in ⑤ touch the network; ④ is fully offline and enough to prove the CLI works.

---

## 1. 下载 / Download

一次性，下载 ~400 MB。该 zip **只含提取器**，查询包在 `database analyze` 时自动拉，不用单独下。
One-off, ~400 MB. The zip contains **extractors only**; query packs are pulled during `database analyze`.

```bash
gh release download v2.27.1 --repo github/codeql-cli-binaries --pattern "codeql-win64.zip"
python -c "import zipfile; zipfile.ZipFile('codeql-win64.zip').extractall('.')"
./codeql/codeql version          # expect 2.27.1 / 应打印 2.27.1
```

| 平台 / Platform | `--pattern` |
| --- | --- |
| Windows x64 | `codeql-win64.zip` |
| Linux x64 | `codeql-linux64.zip` |
| macOS Intel | `codeql-osx64.zip` |
| macOS Apple silicon | `codeql-osx-arm64.zip` |

- 先用 `zipfile.ZipFile(...).testzip()` 校验完整性；Python 的 `zipfile` 比 `unzip` 稳。
  Validate first with `zipfile.ZipFile(...).testzip()`; Python's `zipfile` is more reliable than `unzip`.
- 查最新版本 / Latest version:
  `gh api repos/github/codeql-cli-binaries/releases/latest --jq .tag_name`
- 实测下载很慢（约 15 分钟），放后台跑。
  In practice the download is slow (~15 min) — run it in the background.
- **国内/离线场景见 §5**（镜像、预建 DB、免联网用法）。
  **Domestic / offline options — see §5** (mirror, pre-built DB, no-network usage).

---

## 2. 解压并加入 PATH / Extract & add to PATH

解压后得到 `./codeql/codeql`：
After extraction you get `./codeql/codeql`:

```bash
python -c "import zipfile; zipfile.ZipFile('codeql-win64.zip').extractall('.')"
ls codeql/codeql        # 确认二进制存在 / confirm the binary exists
```

把 `codeql` 目录加入 PATH（任选其一 / pick one）：

```bash
# Linux / macOS（写入 shell 配置后重开终端）
export PATH="$PWD/codeql:$PATH"

# Windows (PowerShell, 持久化)
setx PATH "$env:PATH;$PWD\codeql"
```

> **不想配 PATH 也行**：`bisect_taint.py` 用 `--codeql /abs/path/to/codeql` 直接指绝对路径即可，完全不需要 PATH。
> **No PATH needed**: pass `--codeql /abs/path/to/codeql` to `bisect_taint.py` and you never configure PATH.

---

## 3. 验证安装 / Verify the install

两条命令都能离线跑，用来确认 CLI 与提取器正常：
Both commands run offline and confirm the CLI + extractors work:

```bash
codeql --version            # 期望打印 2.27.1（或你下载的版本）/ expect the version you downloaded
codeql resolve languages    # 期望输出里含 python / expect "python" in the list
```

- 若 `codeql --version` 报 `command not found` → PATH 没生效（回到 §2 重开终端，或用绝对路径 `/abs/codeql/codeql`）。
  If `command not found` → PATH not effective (reopen the terminal, or use the absolute path `/abs/codeql/codeql`).
- 若 `resolve languages` 不含 `python` → 解压不完整，重新下载/解压。
  If `python` is missing from `resolve languages` → extraction incomplete, re-download/extract.

---

## 4. 最小试跑（验证 CLI 是否真的可用）/ Minimal try-run

建一个最小 Python 数据库，成功即证明 CLI + 提取器可用，**无需任何查询包、不联网**：
Build a minimal Python database; success proves the CLI + extractors work, **no query pack, no network**:

```bash
codeql database create /tmp/db --language=python
# 期望看到 "Successfully created database(s) at /tmp/db" / expect "Successfully created..."
```

这一步是「装好没装好」的硬验证——在信任一次真实 triage 之前先跑它。
This is the hard check that the CLI is usable before you trust a real triage run.

---

## 5. 国内与离线选项 / Domestic & offline options  ← R6

CodeQL CLI 的下载源是 `github.com`，国内网络环境可能偏慢。可选方案（**纯提示，按需采用**）：
The CLI is downloaded from `github.com`, which can be slow in some regions. Options (hints only, adopt as needed):

1. **镜像 / 代理**：若你的环境提供 GitHub 镜像或代理，把 §1 的 `gh release download` 走镜像即可；二进制本身不含任何受限内容。
   **Mirror / proxy**: route the §1 `gh release download` through a GitHub mirror or proxy available in your environment.
2. **预建数据库 + 随附查询包**：在有访问能力的机器上先 `codeql database create` 产出 DB，并把 `~/.codeql/packages`（首次 `analyze --download` 拉下来的查询包）一并拷到离线机器。之后 `--codeql /abs/path` 指向本地二进制即可完全离线跑。
   **Pre-built DB + carried packs**: on a machine with access, build the DB and copy `~/.codeql/packages` (the packs pulled by the first `analyze --download`) to the offline machine; then `--codeql /abs/path` runs fully offline.
3. **零依赖两步永不需 CodeQL**：预筛（`scan_sensitive_sources.py`）和读 SARIF（`read_sarif.py`）**完全不碰 CodeQL**，任何装有 Python 的机器都能跑——只有第 ③ 步变体二分才需要本节安装的 CLI。换言之，**核心判定不依赖一次海外大体积下载**。
   **The two zero-dependency steps never need CodeQL at all**: the prefilter and SARIF reader run on any Python machine; only step ③ needs the CLI installed here. In other words, the core judgement does not depend on one large overseas download.

---

## 6. 建库 + 跑单条查询 / Build a database + run a single query

**Run only the rule you care about** — never the whole **query suite** (a CodeQL *query collection* — unrelated to system services or scheduled tasks; `python-code-scanning.qls` takes tens of
minutes).

**只跑目标那一条**，别跑整个 **query suite（查询套件，CodeQL 的查询集合概念，与系统服务/计划任务无关）**（`python-code-scanning.qls` 要几十分钟）。

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
