# 测试夹具

这些文件是**实测产物**，不是手写的示例。

## `repro/` 与 `repro_fixed/`

一对最小复现，各 25 行：

```python
SECRET_PATTERNS    = ["sk-[A-Za-z0-9]{20,}", "ghp_[A-Za-z0-9]{36}"]   # repro/        -> 报 error
CREDENTIAL_PATTERNS = ["sk-[A-Za-z0-9]{20,}", "ghp_[A-Za-z0-9]{36}"]  # repro_fixed/  -> 干净
```

**两份文件除这个变量名外逐字节相同**（`tests/run_tests.py` 里有一项断言守着，
把 `repro` 里的这个名字全局替换掉后必须与 `repro_fixed` 完全相等）。
两份都**不含任何凭据**——只有正则字符串，逻辑是「匹配文本 → 写 JSON」。

### 为什么会触发

CodeQL 的 source 走**名字启发式**，不看内容：

```text
shared/concepts/codeql/concepts/internal/SensitiveDataHeuristics.qll
  maybeSecret() = (?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*
```

`SECRET_PATTERNS` 命中，于是「赋值给它的那个列表」成为 source；
taint 沿循环变量 → `dict` → `json.dumps(...)` 传播，最后落到 `Path.write_text`（sink）。
换成 `CREDENTIAL_PATTERNS` 后名字不再命中，整条路径消失。

详见 [`../../references/sensitive-data-heuristics.md`](../../references/sensitive-data-heuristics.md)。

## `sarif/`

对上面两个目录各建库、跑同一条查询得到的**真实 SARIF**：

| 文件 | 查询 | 结果数 |
| --- | --- | --- |
| `repro.sarif` | `codeql/python-queries:Security/CWE-312/CleartextStorage.ql` | 1 |
| `repro_fixed.sarif` | 同上 | 0 |

生成环境：CodeQL CLI **2.27.1** / `codeql/python-queries` **1.8.11**。

因为有这两份文件，`tests/run_tests.py` 和 CI **不需要安装 CodeQL** 就能验证
`read_sarif.py` 的行为（含 `codeFlows` 里 source 行与流终点的解析）。

> ⚠️ 若你改动了 `repro/scan.py` 的行数，这两份 SARIF 里的行号就失效了
> （测试会红）。重新生成即可，见下。

## 重新生成

```bash
# 需要已安装 CodeQL CLI
python scripts/bisect_taint.py \
    --source scan.py \
    --tree tests/fixtures/repro \
    --workdir /tmp/taint_bisect \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql

cp /tmp/taint_bisect/t1_control.sarif   tests/fixtures/sarif/repro.sarif
cp /tmp/taint_bisect/t2_rename.sarif    tests/fixtures/sarif/repro_fixed.sarif
python tests/run_tests.py
```

顺带一提：这条命令同时验证了 `bisect_taint.py` 自己 —— `t1_control` 必须报 1 条，
`t2_rename` 必须报 0 条，且 `t2_rename/scan.py` 应与 `repro_fixed/scan.py` 逐字节相同。
