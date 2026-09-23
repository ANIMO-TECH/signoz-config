# 接入补齐审查

R1：基线、契约、版本。重新读取生产版本 Coolify4.3.23、SigNoz0.97.1，JobScheduler master f3d80d9。定位旧归档无法补出来源端不存在的操作。补丁绑定上游 commit；Livewire 返回不是业务成功；SigNoz HTTP 响应不冒充异步业务完成。基线中间件和新增测试在本地通过。

R2：安全与故障隔离。发现 Git 仓库 URL 可能携带 token，改为严格 GitHub repo 解析；模型仅存字段名；后台 deployment 身份为空；事务保存标记 pending。原生日志失败捕获；SigNoz 有界队列并验证满队列不阻塞，API Key owner 与 JWT user 分开。PHP 运行时与 Linux race/镜像集成由 CI 验证，尚未完成前不标通过。

R3：运行时集成与发布配置。发现隔离 SQLite fixture 缺 Server 软删除字段，补齐 deleted_at 后重验真实 delete hook；发现 SigNoz 启动检查应使用 --version，按源码 cmd/root.go 修正。两个平台镜像在真实上游运行时构建成功；最终 CI 复验中。生产未部署、实际平台 UI 端到端未测。

R4：操作范围与发布影响。将 Coolify 审计文件切到独立 storage/audit 挂载，避免遮蔽同事原有 storage/logs；collector 仅获审计目录只读权限。发现 delete 事件可能携带此前 update 的 getChanges，改为只在 updated 事件记录字段名并增加断言。核对 LIVEWIRE 官方固定版本 listen/call finish 协议，回调不覆盖返回值。最终 CI 正在复验修复后的源补丁、真实运行时及镜像。
