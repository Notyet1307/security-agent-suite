# 需求—架构—阶段追踪矩阵

| 业务需求 | 当前骨架 | 真实能力建设阶段 | 主要验收 |
| --- | --- | --- | --- |
| 五个独立可调用入口 | `configs/agents.json`、HTTP API、`sasctl` | M0/M1 | 5 个 Agent 均可创建独立 Run |
| 多源流量与攻击链还原 | Traffic Pack、Schema、capset | M2/M6 | 时间线和路径均引用 Evidence |
| 告警定性定级与处置方向 | Event Pack、假设检验 Skill | M2/M5 | 支持证据、反证、缺口和分类齐全 |
| 漏洞与攻击路径验证 | Attack Pack、Scope/Approval Gate | M2/M7 | 零超范围、零未审批主动调用 |
| 法规标准检索与解释 | Compliance Pack、引用 Skill | M2/M4 | 引用存在、版本正确、适用性明确 |
| 日/周/月报和 Word | Report Pack、指标/模板 Skill | M2/M3 | 数字 100% 可复算，Word 可编辑 |
| 证据可追溯 | Run Result、Evidence/Finding 契约 | M2 | 高风险 Finding 证据覆盖 100% |
| 独立工具权限 | `capset_ids`、能力目录 | M1/M2 | Agent 不能调用未授权能力 |
| 主动验证安全控制 | Go Policy + Approval + gated capset | M7 | 双重策略门和停止条件生效 |
| 私有化交付 | Docker/K8s 起步文件 | M9 | 离线安装、升级、回滚和审计通过 |
