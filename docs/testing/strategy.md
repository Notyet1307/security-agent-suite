# 测试策略

## 测试金字塔

1. **领域单元测试**：状态机、策略、ID、路径和幂等；
2. **适配器契约测试**：Store、Artifact、Executor、OctoBus service；
3. **HTTP 集成测试**：认证、租户、请求、审批、取消和下载；
4. **Sandbox 集成测试**：真实 agent-compose 和 Provider；
5. **Agent 离线评测**：事实、证据、稳定性、安全和成本；
6. **客户验收**：真实但脱敏的业务场景。

## 必测失败路径

- 无效 JSON、未知字段、超大请求；
- request_id 冲突；
- 队列满、服务关闭、重启恢复；
- executor 不可达、超时、取消、异常退出；
- Agent 非 JSON、Schema 不匹配和证据缺失；
- Artifact 路径穿越、跨租户访问；
- 未授权主动验证、范围漂移和审批伪造；
- 提示注入、恶意工具输出和敏感信息泄漏。

## 当前命令

```bash
make verify
make race
make smoke
```

设置 `SAS_VERIFY_AGENT_COMPOSE=1` 后，`make verify` 还会运行 agent-compose 配置校验。
