# references/ · 目录索引

本目录存放「深读材料」，SKILL.md / README.md 正文只引用、不重复其内容。
按需查阅即可，不必通读。

| 文件 | 用途 | 适合什么场景 |
|---|---|---|
| [`running-codeql-cli.md`](./running-codeql-cli.md) | 安装 / 验证 CodeQL CLI 的完整步骤链 | 第 ③ 步 `bisect_taint.py` 报「codeql 不存在」，或你从未装过 CodeQL |
| [`sensitive-data-heuristics.md`](./sensitive-data-heuristics.md) | 名字启发式规则原理速查（正向 7 类 source + 反向排除器） | 想搞懂 `scan_sensitive_sources.py` 为什么把某些名字判成敏感、某些不算 |
| [`faq.md`](./faq.md) | 高频问题集中收口 | 基线没复现怎么办 / 复杂改动怎么做变体 / 能不能直接 dismiss / 哪些名字不算敏感源 |

> 三步工作流、退出码契约、命令模板等「主干内容」在 `SKILL.md` 与仓库根 `README.md`；
> 这里只放「展开讲才清楚」的支线材料。
