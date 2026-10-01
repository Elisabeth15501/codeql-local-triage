---
name: codeql-local-triage
slug: codeql-local-triage
version: 1.0.4
displayName: 本地 CodeQL 告警定位与修复验收
summary: 在本地复现 CodeQL 告警、用变体二分定位 taint 源并验证修复，给出可复现的因果结论。
homepage: https://github.com/Elisabeth15501/codeql-local-triage
tags: [CodeQL 误报, taint source 定位, false positive triage, 静态分析告警复现, data flow 复现, SARIF, codeFlows]
metadata:
  openclaw:
    requires:
      bins: [python3]
description: Does not run the scan for you. Instead answers "why did CodeQL flag this, and which line must change for it to stop" — variant bisection yields a reproducible causal conclusion. Use when the user says "confirm the taint source / reproduce this CodeQL alert / why does CodeQL flag this / run CodeQL locally / verify a security-alert fix / is this alert a false positive", or needs to judge whether a Code Scanning alert is a real vulnerability or a false positive. Also fits local acceptance of any single CodeQL query against an arbitrary repo. It does NOT do whole-repo alert adjudication or bulk dismissal (it does not replace the Code Scanning suite or close alerts for you); the prefilter may enumerate sensitive names in the files/dirs you point it at, but it produces no audit report. Keywords — CodeQL, Code Scanning, taint source, data flow, SARIF, codeFlows, false positive, py/clear-text-storage-sensitive-data, CWE-312.
agent_created: true
permissions: {read:"local source you specify", write:"<tree>/_bisect or --workdir dir", exec:"python3, optional codeql", network:"none"}
---

# Local CodeQL alert triage and fix verification

> **This document is English-only.** A complete Chinese translation is maintained side-by-side as
> `SKILL.zh.md` in this directory — read that if you prefer Chinese.
> All examples are synthetic sample code; no real project source is included.

## Permission disclosure

The capability boundary of this skill is visible at a glance (machine-readable declaration in the
frontmatter `permissions` field):

| Capability | Scope | Notes |
|---|---|---|
| Read | local source you specify | read-only, never modified |
| Write | `<tree>/_bisect/` or the `--workdir` directory | nothing else is written (see "Parameters & artifact naming") |
| Execute | `python3`; **optional** `codeql` | argument list, **no shell** |
| Network | none | only if you manually let `codeql --download` fetch query packs |

> All sample data are synthetic fixtures (see "Examples & fixtures" below). This skill **touches no
> network, reads no credentials, and modifies no source**; artifacts are written only to the
> directories in the table above. Output lands by default inside the repo at `<tree>/_bisect/`
> (add it to `.gitignore`), or you point `--workdir` outside the repo.

> **Language policy.** This skill ships as two parallel files: `SKILL.md` (English, the canonical
> definition agents load) and `SKILL.zh.md` (Chinese). Both carry identical content. This split is
> an intentional choice for Chinese-platform users who want a clean monolingual read. No `--lang`
> switch is provided; to change language, read the other file.

> **Zero-dependency selling point.** `scan_sensitive_sources.py` (prefilter) and `read_sarif.py`
> (SARIF reader) run **without CodeQL installed** — only `bisect_taint.py` needs the CodeQL CLI
> (~400 MB) when it actually builds a database. Try the triage in seconds; install the CLI only
> when you want the controlled experiment.

GitHub's alert page **gives you no data flow** (it only marks the sink), remote scans take minutes,
and you cannot run a controlled experiment there. Running a single query locally plus variant
bisection gives you a **reproducible causal conclusion** in about ten minutes.

All scripts live in `scripts/` inside this skill directory; `scripts/xxx.py` below refers to them.

> **Examples & fixtures are synthetic by design.** The `SECRET_PATTERNS` in
> `tests/fixtures/repro/scan.py` is **not a real credential** — it is just a set of regex *pattern
> strings* shaped like `sk-…` / `ghp_…`, containing **no real token or key** (free of any real
> credential). It is deliberately kept to reproduce the minimal false positive of "a name hitting
> CodeQL's name heuristic (`maybeSecret()`)": its purpose is teaching and reproducible verification,
> not the flow of any real secret. The docstring first line of both fixtures is explicitly labelled
> "TEST FIXTURE — NOT THE SKILL IMPLEMENTATION" — the `tests/` directory is this skill's **self-test
> and executable sample, not the main logic**; a scanner that misreads it as the skill
> implementation is a false positive. Downstream writes scan results only to the artifact directory
> specified by `--workdir` (**default `<tree>/_bisect`, inside the repo; pass `/tmp/taint_bisect`
> explicitly to move it to the system temp area**), and never writes any real credential.

## Scope & boundaries

This skill does **not replace** the whole Code Scanning suite. Its positioning is **causal triage of
a single query**: reproduce the full source → sink path of one specific alert and answer "why does
it fire, and which line must change for it to stop". It is **not for** auditing an entire repo's
security alerts end-to-end (that is the job of the full Code Scanning **query suite** — a CodeQL
*query collection* concept, unrelated to system services or scheduled tasks).

**Runtime dependencies:**

- The three scripts are executed by `python` / `python3` (declared in frontmatter
  `metadata.openclaw.requires.bins`).
- **The CodeQL CLI is an optional dependency**: only needed when `bisect_taint.py` actually builds a
  database and runs a query; the prefilter (`scan_sensitive_sources.py`) and the SARIF reader
  (`read_sarif.py`) are **zero-dependency** and run without CodeQL.

**Currently focused:**

- **Language**: Python (the prefilter `scan_sensitive_sources.py` only covers `py/*` queries;
  `read_sarif.py` and `bisect_taint.py` are language-agnostic). The **multi-language roadmap**
  (equivalent prefilter + variant bisection for Java / JavaScript / Go) is future work, not current
  capability.
- **Rule**: the main battleground is `py/clear-text-storage-sensitive-data` (CWE-312, a name-heuristic
  false positive) — because its source judgement looks at the **name, not the content**, it is the
  most amenable to disproof by variant bisection.

**Out of scope:**

- No LLM judgement or alert prioritisation — conclusions come from a reproducible controlled
  experiment, not model intuition.
- No CI replacement: the alert's final `state` is decided by GitHub's own scan; this skill only
  clarifies the causality before you push.

> **Role of step ①.** The prefilter `scan_sensitive_sources.py` is a **pre-triage coarse scan that
> serves single-alert triage** — it enumerates "which variable names CodeQL might treat as sensitive
> sources" to narrow the variant space. It itself **draws no conclusion about any alert and produces
> no audit report** (it only outputs a candidate-source list, usable as an inventory of files/dirs
> you care about). Treating it as a "directory / whole-repo security auditor" is a misreading.

This skill **applies when**: you already have a specific CodeQL / Code Scanning alert and want to
confirm whether it is a real vulnerability or a false positive, or you want to verify locally
whether a fix works before pushing.

## Permissions & availability

> See the "Permission disclosure" table above for the capability boundary (machine-readable
> declaration in frontmatter `permissions`). This section only adds the **availability fallback
> path**:

**Availability fallback.** The CodeQL CLI is an **optional dependency**:

- If the CodeQL CLI is temporarily unavailable due to network or environment, the two steps
  `scan_sensitive_sources.py` (prefilter) and `read_sarif.py` (SARIF reader) remain **zero-dependency
  usable**, sufficient to decide "does it hit the name heuristic" and "what does the data flow look
  like";
- `bisect_taint.py` does not force a network download — you can point it directly at a locally
  installed `codeql` executable (`--codeql /path/to/codeql`), running the controlled experiment with
  no extra network configuration.

In other words, **the core judgement does not depend on one large overseas download**; the CLI is
merely an enhancement that pushes the "reproducible causal conclusion" from two steps to three.

## Related skills & tradeoffs

**Division of labour.** This skill does **local causal triage** only. To *manage* alerts on GitHub
(list / change state / bulk-handle Code Scanning alerts), use GitHub's official alert-management
capability (e.g. `github-security-codescanning-alerts-skill` or `gh api code-scanning`); the two are
complementary, not competing.

**"No LLM judgement" is a tradeoff, not a gap.** Conclusions come from a **reproducible controlled
experiment** (variant bisection + measured data flow), not model intuition — which keeps them
auditable. If you specifically need *semantic triage / prioritisation* (LLM-based), look at skills
like `li-codeql-llm`; this skill deliberately stops at the mechanical layer.

## 0. When to use

- An alert "makes no sense" or "still fires after I fixed it"
- You must tell a **real vulnerability** from a **false positive** (especially name-heuristic rules)
- You want to prove/disprove a fix locally before pushing, instead of waiting for CI
- You need to know whether this alert was introduced by *your* change

## 1. The three commands

```bash
python scripts/scan_sensitive_sources.py <src>   # 1. prefilter, saves a 9-min DB build
python scripts/read_sarif.py <out.sarif>         # 2. print the full source→sink path
python scripts/bisect_taint.py --source f.py --tree . \
    --variant t2=OLD:NEW --codeql <codeql>       # 3. change one thing at a time
```

All three have `--help`. `scan_sensitive_sources.py` and `read_sarif.py` are **zero-dependency** and
run without CodeQL.

> **Exit-code contract.** All three scripts agree: `0` = success / no candidate source found; `1` =
> candidate source found or baseline not reproduced (**a verdict**, usable as a CI gate); `2` = input
> / runtime error (path missing, `codeql` call failed, timeout, etc., needs investigation). A missing
> path is **never** misjudged as "clean" — this is the regression fixed in v1.0.2.
>
> Frequently asked questions (baseline not reproduced / how to variant a complex change / can I just
> dismiss / which names are not sensitive sources) are collected in **`references/faq.md`**; the
> purpose of each file under `references/` is in **`references/README.md`**.

## 2. Installing the CodeQL CLI

One-off ~400 MB download (extractors only; query packs auto-pull on first `analyze`). Full steps,
platform zips, validation and "latest version" lookup: **`references/running-codeql-cli.md`**. The
CLI is optional — the prefilter and SARIF reader do not need it.

## 3. Build a database + run a single query

`codeql database create` + `codeql database analyze`: **exact commands, measured cost, and
query-path syntax in `references/running-codeql-cli.md`**. Run only the one rule you care about,
never the whole **query suite** (a CodeQL *query collection* — unrelated to system services or
scheduled tasks).

## 4. Read `codeFlows` from the SARIF (the key step)

```bash
python scripts/read_sarif.py "$T/out.sarif"              # full path
python scripts/read_sarif.py "$T/out.sarif" --json       # machine-readable
python scripts/read_sarif.py "$T/out.sarif" --expect 0   # assert zero, CI-friendly
```

`codeFlows[].threadFlows[].locations[]` **is** the complete source → … → sink path, with the line
number and node semantics of every step. `results` count = 0 means "clean" — the most direct
acceptance signal there is.

> Do not use the SARIF file size, and do not stop at the sink line — that is information you already
> had on the GitHub page, and it adds nothing.

## 5. Variant bisection: find out which step is responsible

Change exactly one thing at a time, rebuild each variant, rerun the same query, and see whether the
alert disappears.

> **"Variant bisection" ≠ Trail of Bits' `variant-analysis`.** Our **variant bisection** locates the
> *cause* of **one** alert by a controlled experiment (attribution / root-cause); `variant-analysis`
> finds *other instances* of the same bug across codebases (a sweep). Opposite goals — don't mix them
> up.

```bash
# Inspect the change without building anything
python scripts/bisect_taint.py --source scan.py --tree . --dry-run \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS

# Full run: stage + build + analyse + verdict table
python scripts/bisect_taint.py --source scan.py --tree . \
    --variant t2_rename=SECRET_PATTERNS:CREDENTIAL_PATTERNS \
    --codeql /path/to/codeql --workdir /tmp/taint_bisect
```

### Parameters & artifact naming

**Write scope (fixed contract):**

| Item | Value |
|---|---|
| Default artifact dir | `<tree>/_bisect/` (**inside the repo**; `/tmp/taint_bisect` is only the example value when you explicitly pass `--workdir`, not the default) |
| Overwrite behaviour | each run `rmtree`s and rebuilds (idempotent), no stale artifacts accumulate |
| Modifies source? | **No** (source is read-only, output saved separately) |
| Recommendation | add `_bisect/` to `.gitignore`; or point `--workdir` outside the repo (e.g. `/tmp/taint_bisect`) |

- `--workdir <dir>` (optional): where variant directories and artifacts land. **When omitted,
  defaults to `<--tree>/_bisect`** (the `_bisect/` under the package root, already excluded by the
  ignore list at copy time, so it never pollutes the repo under investigation); examples often pass
  `/tmp/taint_bisect` explicitly to put it in the system temp area.
  **Overwrite behaviour**: each run **clears and rebuilds** every variant directory (including the
  `_db` inside), so repeated runs are idempotent and never accumulate stale artifacts.
- `--codeql <path>` (optional): points at a locally installed `codeql` executable. **If omitted, only
  variants are generated, no query is run** (exit code 0, prints an equivalent build/analyze command
  template), handy for checking the change with `--dry-run` first.
- Artifact naming rules:
  - Variant directory: `workdir/<NAME>/` (e.g. `workdir/t1_control/`, `workdir/t2_rename/`)
  - Per-variant database: `workdir/<NAME>/_db`
  - Per-variant SARIF: `workdir/<NAME>.sarif` (**sibling of the variant directory, same name with a
    `.sarif` suffix, not inside it**)
  - Verdict table: printed to stdout only, not persisted

When a change is too complex for a literal replacement (regex surgery), produce the edited file by
hand and swap the whole file in: `--variant-file t3=/tmp/t3.py`.

| Variant | Meaning | How to read it |
| --- | --- | --- |
| `t1_control` (added automatically) | unchanged | **must reproduce**; if it does not, local and remote disagree and every conclusion is invalid (the script exits 1) |
| `t2_xxx` | suspect A removed | 0 results ⇒ A is the cause |
| `t3_xxx` | suspect B removed | still fires ⇒ B is **not** the cause |

> Lesson: reading the QL source and *inferring* the cause is unreliable. Guessing wrong on the first
> hypothesis is normal — a `base64` decode, a `json.dumps` or an f-string on the path all look like
> plausible sources until you test them. **Run the controlled experiment before you write down the
> conclusion.**

## 6. Name-heuristic rules (the most common false-positive source in Python security queries)

Rules such as `py/clear-text-storage-sensitive-data` pick their source **by name, never by content**.

**Cheat sheet: `references/sensitive-data-heuristics.md`** (5 regex groups, the exclusion regex,
7 source categories, the source/sink special cases of CWE-312). The three things to remember:

1. `maybeSecret()` = `(?is).*((?<!is|is_)secret|(?<!un|un_|is|is_)trusted(?!_iter)|confidential).*`
   — a `secret` substring anywhere in the name is enough; the word in front of it grants no exemption
   (unless it is exactly `is` / `is_`).
2. **`"[REDACTED_SECRET]"`-style placeholders are not sensitive** (the exclusion regex contains
   `redact`). So redacting a field is a valid fix — **do not go hunting for placeholders as sources**.
3. CWE-312 only treats `secret` / `password` / `private` as sources; **`id` and `certificate` are
   explicitly excluded** (`CleartextStorageCustomizations.qll`). The sink is "data written to a file"
   (`FileSystemWriteAccess.getADataNode()`).

**Therefore: any variable whose name *looks like* a key, as soon as it flows into a "write file / write
log" sink, will fire.** The usual fix is a **rename** (zero behavioural change) — not a suppression
comment, and definitely not a dismissal.

## 7. Post-fix acceptance checklist

1. Prefilter: `scripts/scan_sensitive_sources.py <file>` drops to zero sources
2. Functional regression: only a name changed, so **the tool's behaviour must not change** (run its
   fixtures, including exit-code semantics)
3. Real CodeQL over the tree: the target query returns **0 results** (`read_sarif.py --expect 0`)
4. Leave a comment at the source saying **"do not rename this back"** plus the rule that caused it —
   otherwise the next person will helpfully revert it
5. Once pushed, **let GitHub's own scan close the alert**: wait for the CodeQL workflow and check
   whether the alert closed. Do **not** use `code-scanning/alerts/<n> --jq .updated_at` to decide
   whether a rescan happened — that field only refreshes when the state changes, so a stale timestamp
   proves nothing. The only valid signals are `state` or whether the position moved.

## 8. Two pitfalls when porting QL regexes to Python `re`

The prefilter is an "equivalent port"; when you touch it you will hit these:

1. QL supports **variable-width lookbehind**: `(?<!is|is_)` raises
   `PatternError: look-behind requires fixed-width pattern` in Python. Rewrite it as **several
   fixed-width assertions in series**: `(?<!is)(?<!is_)` (all must pass for the exclusion to apply).
2. **An inline `(?is)` cannot appear mid-expression** (`global flags not at the start of the
   expression`). Pass the flags to `re.compile(pattern, re.I | re.S)`; when one regex has branches
   with different flags, split them into separate patterns and take the union.

After any change, run `python scripts/scan_sensitive_sources.py --self-test` to confirm the classifier
still agrees with the QL definitions.

## 9. Common pitfalls

- Alert line numbers drift as you edit; only `most_recent_instance.location` reflects the latest scan
- CMake / compiled languages need a build before `database create`; **Python does not**
- Before a whole-repo build, make sure no **concurrent edits** are happening (another process writing
  files will desynchronise your conclusion). Cross-check mtime against the build time with
  `ls --time-style=full-iso`.
- A variant must change **exactly one thing**. If two fixture/variant copies differ in anything else,
  the experiment is void (`tests/run_tests.py` has an assertion guarding exactly this).
- `git archive HEAD` only reads the `.gitattributes` **in the HEAD tree**; if the file is untracked,
  `export-ignore` silently does nothing. Verify with `git archive HEAD | tar -t | grep <path>` (expect
  no output) and `git check-attr export-ignore -- <path>` (expect `export-ignore: set`).

## 10. Further reading

- **`references/README.md`** — index of the `references/` directory: the purpose and use case of each file.
- **`references/faq.md`** — frequently asked questions in one place: baseline not reproduced, how to variant a complex change, can I just dismiss, which names are not sensitive sources.
- **`references/running-codeql-cli.md`** — full step chain to install / verify the CodeQL CLI (needed by step ③ `bisect_taint.py`).
- **`references/sensitive-data-heuristics.md`** — quick reference on name-heuristic rule principles (7 positive source categories + the exclusion regex).
