# CodeQL Python 安全查询的「敏感数据」名字启发式

本文件是排查时最常回查的一张表：**哪些变量名会让 CodeQL 认定「这是敏感数据」**。

内容逐字摘自 [github/codeql](https://github.com/github/codeql)（MIT License，见文末署名）：

| 来源文件 | 提供什么 |
| --- | --- |
| `shared/concepts/codeql/concepts/internal/SensitiveDataHeuristics.qll` | 名字正则（`maybeSecret` 等）与反向排除器（`notSensitiveRegexp`） |
| `python/ql/lib/semmle/python/dataflow/new/SensitiveDataSources.qll` | 7 个 source 类 |
| `python/ql/lib/semmle/python/security/dataflow/CleartextStorageCustomizations.qll` | CWE-312 取哪些 source、sink 是什么 |

> 本文只解释「为什么会误报」。**不要**据此去关闭真实告警——先看 `scripts/read_sarif.py` 打出的数据流。

---

## 1. 判定入口：名字，而不是内容

`SensitiveDataSources.qll` 里所有 source 都要求名字命中 `maybeSecret()` / `maybePrivate()` 等启发式。
它们**完全不看变量里装的是什么值**。所以：

```python
SECRET_PATTERNS = ["sk-[A-Za-z0-9]{20,}"]   # 里面只是一串正则，但名字命中了 -> 被当敏感数据
CREDENTIAL_PATTERNS = ["sk-[A-Za-z0-9]{20,}"]  # 换个名字就不再敏感，逻辑零变更
```

## 2. 五组分类与对应正则

### `maybeSecret()` → classification `secret`

```text
(?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*
```

- 命中：`SECRET_PATTERNS`、`secret_key`、`oauth_secret`、`confidential_data`
- 不命中：`is_secret` / `is_secret_…`（前缀 `is`、`is_` 排除）、`untrusted` / `un_trusted` / `untrusted_iter`
- 容易踩：变量里只要含 `secret` 子串就够——**它前面的词不构成豁免**，除非正好是 `is` / `is_`

### `maybePassword()` → classification `password`

```text
(?is).*(pass(wd|word|code|.?phrase)(?!.*question)|(auth(entication|ori[sz]ation)?).?key|oauth|api.?(key|tok)|([_-]|\b)mfa([_-]|\b)).*
```

- 命中：`api_key`、`api_token`、`oauth_client`、`mfa_code`、`auth_key`
- 注意 `passphrase` / `pass_phrase` 都算；但后面跟 `question`（`passphrase_question`）会被排除

### `maybeAccountInfo()` → classification `id`

```text
(?is).*(acc(ou)?nt|puid|user.?(name|id)|session.?(id|key)).*
(?s).*([uU]|^|_|[a-z](?=U))([uU][iI][dD]).*
```

- 命中：`account_id`、`username`、`user_id`、`session_key`、`uid`、`customerUid`

### `maybeCertificate()` → classification `certificate`

```text
(?is).*(cert)(?!.*(format|name|ification)).*
```

- 命中：`client_cert`、`cert_pem`
- 排除：含 `cert_format` / `cert_name` / `certification` 的不算

### `maybePrivate()` → classification `private`

信用卡、身份证/护照、住址、电话、生物特征、医疗、employer、`mac_addr` 等一长串。
完整正则见 `scripts/scan_sensitive_sources.py` 里的 `MAYBE` 常量（第 5 组 `private`）。

## 3. 反向排除器 `notSensitiveRegexp()`

即使命中上面的正则，只要还命中下面这条就**不算**敏感：

```text
(?is).*([^\w$.-]|redact|censor|obfuscate|hash|md5|sha|random|(?<!unen)crypt|(?<!un)encode|certain|concert|secretar|wildcard|coauthor|account(ant|ab|ing|ed)|(?<!pro)file|path|([_-]|\b)url).*
```

实践含义（很重要）：

- **`"[REDACTED_SECRET]"` 不会被判敏感** —— `redact` 在排除表里。
  所以「把敏感字段脱敏成 `[REDACTED_SECRET]`」是有效修复，**别把它当成污染源去查**。
- 名字里带 `file` / `path` / `url` / `hash` / `md5` / `encode` 的通常直接出局
  （`profile` 例外：`(?<!pro)file` 表示前面是 `pro` 的 `file` 不算触发排除）
- `swissre` 之类**包含**敏感子串但不是词的名字，靠 `[^\w$.-]` 前的边界规则处理——
  移植到其它语言时务必用**词边界**匹配，否则会误伤。

## 4. 七类 source（`SensitiveDataSources.qll`）

| 类 | 形态 |
| --- | --- |
| `SensitiveVariableAssignment` | `SECRET = ...`（含 `for x in ...` 的循环变量、`with ... as x`） |
| `SensitiveAttributeAccess` | `obj.api_key` |
| `SensitiveSubscript` | `d["api_key"]` |
| `SensitiveGetCall` | `d.get("api_key")` |
| `SensitiveParameter` | `def f(api_key)` |
| `SensitiveFunctionCall` | `get_secret()` |
| `GetPassCall` | `getpass.getpass()` |

## 5. `py/clear-text-storage-sensitive-data`（CWE-312）特例

**source 会再筛一次**——`CleartextStorageCustomizations.qll`：

```ql
class SensitiveDataSourceAsSource extends Source, SensitiveDataSource {
  SensitiveDataSourceAsSource() {
    not SensitiveDataSource.super.getClassification() in [
        SensitiveDataClassification::id(), SensitiveDataClassification::certificate()
      ]
  }
  ...
}
```

⇒ 对**这条查询**而言，只有 `secret` / `password` / `private` 会引爆，
`id`（`user_id`、`session_key`…）与 `certificate` **被显式排除**。

**sink** 是「写入文件的数据」：

```ql
class FileWriteDataAsSink extends Sink {
  FileWriteDataAsSink() {
    this = any(FileSystemWriteAccess write).getADataNode() and ...
```

即 `Path.write_text` / `write_bytes`、`open(...).write(...)` 之类。源码里对 `pathlib.py` 自身做了
carve-out（避免在 `Path.write_bytes` 与内部 `f.write` 之间重复报两条）。

所以完整触发链是：

```text
敏感名赋值 → 沿循环变量/字典/f-string 传播 → json.dumps / str 拼接 → 写入文件
```

## 6. 修复取向

| 做法 | 评价 |
| --- | --- |
| **改名**（`SECRET_PATTERNS` → `CREDENTIAL_PATTERNS`） | ✅ 首选。逻辑零变更，不动数据流，不改公共接口 |
| 把字段真的脱敏（`[REDACTED_SECRET]`） | ✅ 有效，且 `redact` 在排除表里 |
| `# lgtm` / `# codeql[...]` 抑制注释 | ⚠️ 藏住了结论，下一个人仍要重查一遍 |
| 在 GitHub 上 dismiss 告警 | ⚠️ 最后手段。误报要写清理由；**改名能解决的就别 dismiss** |

改完记得在源码里留一句「**勿改回去** + 规则出处」，否则下一个人会顺手把名字改回来。

---

## 署名

本文的正则与 QL 代码片段取自 [github/codeql](https://github.com/github/codeql)，
Copyright GitHub, Inc.，以 MIT License 授权。本文档与本仓库的 `scripts/scan_sensitive_sources.py`
均为对这些定义的可读重述/等价移植，不是 GitHub 官方产物。
