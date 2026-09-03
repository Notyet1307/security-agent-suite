# 参考项目研究与复用边界

> 研究基线：2026-09-03。该文档记录架构借鉴，不表示直接复制代码；许可证以各项目实际文件和具体依赖为准。

## 1. 总览

| 项目 | 仓库许可证 | 借鉴内容 | 不直接复用内容 |
| --- | --- | --- | --- |
| CyberStrikeAI | Apache-2.0 | 安全工作空间、工具治理、攻击链、审批、证据与任务关联 | 不嵌入其完整 Agent 平台和前端 |
| reverse-skill | MIT（仓库根） | Skill Router、Scope Gate、Evidence→Finding→Path、案件流程 | 不无审查复制外部工具或子模块 |
| Anthropic-Cybersecurity-Skills | Apache-2.0 | Skill 组织方式和安全 SOP 候选素材 | 不把大规模 Skill 原样拉进生产 |
| open-kritt | AGPL-3.0 | 任务拆分、并行执行、验证、排序和结果打包思想 | 不复制核心代码进入本 Apache-2.0 仓库 |
| agent-compose | AGPL-3.0 | Agent 声明、Sandbox、Skills、Workspace、运行生命周期 | 不二次实现，不复制源码；作为独立运行时 |
| OctoBus | GPL-3.0 | 企业能力网关、capset、能力代理 | 不把所有工具塞入控制面；作为独立服务 |

## 2. CyberStrikeAI

### 借鉴

- 工作空间中统一管理任务、工具调用、资产、漏洞和攻击链；
- 高风险工具的审批与角色权限；
- 工具执行的超时、取消、并发和结果限制；
- 将执行证据与最终结论绑定。

### 本项目映射

- Go `Run` 状态机承担业务任务生命周期；
- agent-compose 负责 Agent/Sandbox；
- OctoBus capset 负责工具权限；
- Evidence/Finding/AttackPath 契约负责证据关系。

## 3. reverse-skill

### 借鉴

- 先做 Scope/输入检查，再进入场景 Skill；
- 主 Skill 与辅助 Skill 的选择；
- Evidence、Finding、Path 分层；
- 时间线和案件复核。

### 本项目映射

五个 Agent Pack 均把固定 SOP 写入 `SKILL.md`；确定性授权不放在 Skill 中，而由 Go 与工具服务双重执行。

## 4. Anthropic-Cybersecurity-Skills

### 借鉴

- YAML front matter + Markdown 的轻量 Skill 结构；
- 按防御、流量、取证、威胁情报、漏洞与合规分类；
- 将步骤、输入、输出和质量要求写成可版本化文档。

### 进入生产的审核流程

```text
候选 Skill
 → 去重与适用性判断
 → 改写成内部工具名和契约
 → 增加停止条件与证据要求
 → 安全专家评审
 → 固定 commit/SHA
 → Fixture 测试
 → 版本发布
```

当前仓库仅自行编写 15 个基线 Skill，没有批量复制上游内容。

## 5. open-kritt

### 借鉴

- 大任务拆为范围明确的子任务；
- 并行后去重、排序和验证；
- 结果包包含结构化发现、验证产物和 Manifest；
- 把后处理验证视为独立阶段。

### 不采用

- 不让每个工具 Agent 默认获取可写代码副本和互联网；
- 不直接采用其运行时和 root 容器假设；
- 不复制 AGPL 核心实现。

## 6. agent-compose 与 OctoBus

二者不是“参考后重写”的对象，而是明确的外部依赖：

- agent-compose：提供声明式 Agent、Sandbox 和运行生命周期；
- OctoBus：提供企业工具能力的授权代理；
- Security Agent Suite：提供面向客户和业务系统的安全契约、审批、证据和统一 API。

## 7. 代码来源声明

本仓库的 Go 实现、JSON Schema、系统提示和基线 Skill 为独立搭建的参考骨架。未来引入任何第三方文件时，应同步更新：

- `NOTICE`；
- `licenses/`；
- SBOM；
- 来源 commit；
- 修改说明；
- 再分发义务。
