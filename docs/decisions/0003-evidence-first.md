# ADR-0003：证据优先于结论

- 状态：Accepted
- 日期：2026-09-03

## 决策

统一以 `Evidence → Finding → Timeline/AttackPath → Report` 组织数据。模型文本不能替代原始证据。

## 规则

- Evidence 保存来源、工具、版本、参数、时间、哈希和 Artifact；
- Finding 引用 Evidence，并记录置信度和不确定性；
- Timeline/AttackPath 只连接有证据支持的事实或明确标记的推断；
- 报告只引用冻结后的 Finding 和确定性指标；
- 重跑产生新版本，不覆盖历史。

## 结果

评测不只判断“答案像不像”，还可以检查证据覆盖率、引用正确率、时间线一致性和复现率。
