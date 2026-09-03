# 安全模型与威胁边界

## 1. 保护目标

- 客户输入、日志、PCAP、报告和凭据不泄露；
- Agent 不越出授权工具和网络范围；
- 工具调用可归因、可审计、可取消；
- 安全结论可追溯，不能被模型无证据伪造；
- 一个租户不能观察或影响另一个租户；
- 恶意输入不能改变系统指令或执行策略；
- 开源依赖、镜像和 Skill 更新不会无审查进入生产。

## 2. 信任边界

| 区域 | 是否可信 | 处理原则 |
| --- | --- | --- |
| Go 控制面代码和固定策略 | 相对可信 | 代码审查、测试、签名构建 |
| 调用方请求 | 不可信 | Schema、大小、租户、URI、策略校验 |
| 上传文件和目标返回 | 不可信 | 隔离解析、禁止指令继承、资源限制 |
| 模型输出 | 不可信 | Schema、证据引用、业务规则复核 |
| Skill | 条件可信 | 版本固定、评审、测试、禁止运行时拉 main |
| OctoBus 工具 | 条件可信 | 最小权限、参数约束、审计、超时 |
| 外部情报和法规网页 | 不可信内容 | 来源校验、内容与指令隔离 |
| Sandbox | 假设可能被攻陷 | 无长期密钥、网络分区、一次性凭据 |

## 3. 主要威胁及控制

### 提示注入

威胁：日志、代码、网页、PCAP 提取文本或工具响应包含“忽略系统指令”等内容。

控制：

- SYSTEM 明确所有输入和工具输出都是数据；
- 任务信封将 policy 与 untrusted content 分区；
- 高风险动作由 Go/OctoBus 确定性策略决定，而非模型决定；
- 模型不能读取上游永久密钥；
- 对网页和代码分析使用隔离 Sandbox。

### 任意命令执行

威胁：调用方将 Shell 放入请求，或模型拼接命令执行。

控制：

- 对外 API 不存在 command 字段；
- Go 只调用固定的 agent-compose CLI 参数；
- 安全工具必须包装为结构化能力；
- Sandbox 使用非特权运行、只挂载需要的目录；
- 生产攻击验证工具使用独立镜像和网络区。

### 越权主动验证

控制门：

```text
action requested
  AND agent == attack-path-validation
  AND mode == active_validate
  AND authorization_ref exists
  AND explicit target scope exists
  AND network_access == restricted
  AND max_requests/max_duration valid
  AND human approval recorded
  AND OctoBus capability also authorizes method
```

任何一项不满足即拒绝。Go 审批只放行任务；OctoBus 服务仍需再次验证目标和方法，形成双重门。

### 数据外泄

- 默认不允许外部网络；
- 外部情报服务只允许已批准 IOC 字段，不上传原始 PCAP/日志；
- Artifact 按租户和 Run 隔离；
- 日志不记录 API Key、令牌、完整 Prompt 和敏感正文；
- 生产使用 KMS、对象存储加密和生命周期策略；
- 下载接口需要授权并记录审计。

### 供应链风险

- Go 模块、基础镜像和 agent-compose 镜像固定版本；
- Git Skill 固定 commit SHA，不指向移动分支；
- CI 执行 CodeQL、依赖更新检查、SBOM 和镜像扫描；
- 不直接复制 AGPL/GPL 项目源码到 Apache-2.0 仓库；
- 参考项目只借鉴模式，实际代码独立实现。

## 4. Agent 风险等级

| Agent | 默认工具权限 | 高风险写操作 | 必要控制 |
| --- | --- | --- | --- |
| compliance-query | 只读检索 | 无 | 权威来源、版本和引用校验 |
| security-report | 只读数据 + 写报告文件 | 无业务写操作 | 数字确定性计算、脱敏 |
| event-triage | 只读 SOC/资产/终端 | 禁止自动处置 | 反证、证据、建议需审批 |
| traffic-analysis | 只读文件/会话/情报 | 禁止阻断 | 隔离解析、样本外发控制 |
| attack-path-validation | 只读 + 审批后低影响验证 | 严格受控 | 范围、审批、速率、停止条件、双重授权 |

## 5. 生产上线前的硬门槛

- [ ] OIDC/mTLS 替代单一 API Key；
- [ ] PostgreSQL 或等价事务存储；
- [ ] S3/MinIO Artifact 存储、加密和签名 URL；
- [ ] 每个 capset 的方法级权限评审；
- [ ] 主动验证网络分区和出口白名单；
- [ ] secrets 不进入 Agent Prompt、环境日志和 Artifact；
- [ ] 真实样本评测、越权测试和提示注入红队；
- [ ] 镜像 SBOM、签名、漏洞扫描和版本冻结；
- [ ] 灾备、审计导出、留存与删除策略；
- [ ] 开源许可证和客户分发模式复核。
