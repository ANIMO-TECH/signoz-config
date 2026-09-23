# 接入补齐审查

R1：基线、契约、版本。重新读取生产版本 Coolify4.3.23、SigNoz0.97.1，JobScheduler master f3d80d9。定位旧归档无法补出来源端不存在的操作。补丁绑定上游 commit；Livewire 返回不是业务成功；SigNoz HTTP 响应不冒充异步业务完成。基线中间件和新增测试在本地通过。

R2：安全与故障隔离。发现 Git 仓库 URL 可能携带 token，改为严格 GitHub repo 解析；模型仅存字段名；后台 deployment 身份为空；事务保存标记 pending。原生日志失败捕获；SigNoz 有界队列并验证满队列不阻塞，API Key owner 与 JWT user 分开。PHP 运行时与 Linux race/镜像集成由 CI 验证，尚未完成前不标通过。

R3：最终 diff、运行时集成、发布覆盖配置。待 CI 完成后记录实测结果。生产未部署、实际平台 UI 端到端未测。
