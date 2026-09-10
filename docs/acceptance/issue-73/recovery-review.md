独立复核人：`/root/accept73_recovery`（未参与 #72；AI 复核，非真人签字）。
结论：接受本次分配的离线恢复/并发/存储/CLI范围；未发现阻断项。
固定 SHA：`342c9b6d8d6c20f872bd9c71d3b6a1d83300613a`；规格 #70 v3，updated_at `2026-09-10T09:08:22Z`，任务 #73。

已审读公共 API 断言和 app/store 实际路径并执行 5 条 `go test -count=1 -v`：24 个文件/内存×六持久化边界×同实例/重启案例，一次执行/单 Evidence；16 并发提交；取消竞争；满队列5次调用补投；损坏 journal/Evidence/字节/指纹/inputs 启动拒绝；running/validating 不重试；Evidence 伪造/预占；三类同步故障恢复和 Artifact 原文保留；CLI 原始上传/显式提交/preparing/未知状态。全部通过。
独立 overlay 额外证明 submit→cancel→replay→Start 后零执行，另一 Run 不能占用私有 Evidence ID，异租户404。仓库未修改。

原始命令/输出：`/tmp/sas73-recovery-raw.txt`；探针 `/tmp/sas73_independent_recovery_test.go`，overlay `/tmp/sas73-recovery-overlay.json`。
回滚文档明确旧二进制不能接触任何 manual 记录，只能一致备份/隔离目录。未实际执行回滚、真实断电或跨进程 exactly-once；memory 重启是服务实例重建并保留内存适配器。未运行 Provider/daemon/Sandbox/OctoBus/外部目标，不证明模型消费输入或真实研判。全套 verify/race 由主任务另记证据。

补充复核：已 gofmt 临时探针并独立重跑一次，通过（EXIT=0）。实际采样值已写入 raw：calls_after_cancel_replay_start=0；cross_run_public_append_status=409；cross_tenant_public_append_status=404；final_calls=0。状态码由实际 ResponseRecorder.Code 记录，调用数由计数 executor 读取。最终接受结论不变，累计6条测试命令执行（含日志增强复跑），未改仓库。
