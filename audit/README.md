# 内部平台操作日志

独立后台采集 JobScheduler、Coolify、SigNoz 的现有日志，记录操作/请求、时间、对象、结果和来源地址。原生可信账号存在时记录账号或凭证 ID，没有时 `actor=null`。不新增登录、弹窗、平台写接口或删除日志的 UI，也不修改原有应用 Compose。

日志写入独立 S3 兼容对象存储，要求版本化及 **COMPLIANCE Object Lock**。采集账号没有删除权限，独立清理账号每小时清理到期版本。删除源平台上的 Job、部署或看板不会级联删除归档。

## 已实现的链路

```text
只读日志文件 → 白名单解析 → SQLite 持久化队列（事件与读取位置同事务）
            → gzip 批次 → 条件写入 S3 → 校验 SHA / VersionId / 保留锁 → 确认出队
                                 └→ 可选 OTLP/SigNoz 查询副本
独立清理角色 → 每小时按版本检查期限/法律保留 → 删除到期版本
只读查询角色 → export JSONL；可选按 repo+commit 查询关联 PR
```

| 来源 | 支持的实际格式和字段 | 边界 |
|---|---|---|
| JobScheduler | Uvicorn access log，含 Docker JSON 包装；create/update/toggle/delete/run/refresh-health、job ID、HTTP 状态、peer IP | 是请求操作记录；303/200 不冒充业务成功；create 路径没有新 job ID 时保留 null；不采表单/headers/body |
| Coolify 4.3.23 | 原生 `audit.log`：API/webhook/已打点 UI 事件、user_id/token_id、对象/部署 UUID、已提供的 repo/commit；Laravel 空 extra 后缀受支持 | 原生 audit 没覆盖的 UI 动作不能自动补出语义。已有 Traefik JSON access log 可记录 `/livewire/update` 为 `ui.interaction`，不伪称 deploy |
| SigNoz v0.97.1 | `::RECEIVED-REQUEST::` JSON/前缀 JSON；route、状态、peer 地址 | 旧 logger 缺 method 时记录 `dashboard.request`/`platform.request`；不把一次查看误称修改。不以当前最后修改人推断某次请求操作者 |

健康检查、静态资源和 query_range 查询默认过滤；`include_reads=true` 可增加已知只读路由。未知写路由只记规范化的 `http.mutation`；不复制可能带秘密的原始 URL。源时间与接收时间分开；无时区的源时间标记 `timezone_known=false`，不用于保留期。

## 30 天滚动与防删边界

- **30 天 = 30×24 小时，UTC。** 每个事件以第一次采集入队时间计时。批次最多跨一个 UTC 分钟，锁定至该批次最后接收时间 + 30 天（向上取整一秒）；不是每次重试或恢复后重新计时。
- 采集每 60 秒一轮；到期清理每 3600 秒一轮，最多处理 10 页、每页 1000 个版本，保存分页游标，积压时后续轮次继续。删除有批次取整和调度/分页延迟，不承诺第 30 天整点物理删除。
- 接收队列默认最多 **64 MiB JSON payload**。SQLite 主文件硬上限约为这个值的三倍，WAL 定期截断；容器自日志滚动到 2×10 MiB。内存和磁盘不会因无限队列持续增加。大于 64 KiB 的输入行分段丢弃并计数，不复制其正文。
- 队列满时不推进未保存操作的读取位置，平台照常运行；源日志若在追上前被外部删除，无法补回。采集器会报告不可读、超长、截断等状态。建议来源采用 **rename + 保留轮转文件**，避免 `copytruncate`；后者在快速截断并回长或原内容相同的情况下无法保证识别。
- 已准备的批次在重试期间保持内容/ID 不变，条件写入及远端 SHA 校验避免重复覆盖。归档失败不出队；离线超过保留期的队列记录按期清理，输出 `expired_unarchived_events`，不能假称它们成功归档。
- COMPLIANCE 保护**已成功归档的版本**；清理端既检查元数据的 30 天，又检查服务端实际锁和 legal hold。仍在保留期/被延长/有法律保留的版本不会被强行删。缺权限或无法核实时保留并报告。
- 本机未上传队列、源文件、失去源日志读取权限、主机或存储底层被破坏不在对象锁的保护范围。建议桶在独立管理的存储服务上，三个被审计平台不持有归档/清理凭证。不要将“有哈希”解释为无法删除；防删依赖实际对象锁和权限隔离。
- `policies/lifecycle.json` 是独立桶的清理兜底：清理进程异常时，由存储生命周期按写入对象时间过期/清理非当前版本及 delete marker；对象锁仍优先。此兜底异步执行，通常比主清理更晚，不能用它宣称准点删除。部署时必须核对并监控归档/清理状态及容量。

## 安装和本地命令

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -e .
cp config.example.toml config.toml
```

在 `config.toml` 填专用桶及真实日志只读路径。配置文件只放非秘密标识。凭证采用 AWS SDK 标准凭证链；`AUDIT_S3_ENDPOINT` 可指向支持 Object Lock 的 S3 兼容服务，生产要求 HTTPS（仅 loopback 测试允许 HTTP），不关闭 TLS 校验。`AWS_DEFAULT_REGION` 按存储服务设置。

```sh
# 使用 writer 角色，检查桶版本化/30天COMPLIANCE配置。
platform-audit check --config config.toml
platform-audit collect --config config.toml --once
platform-audit collect --config config.toml

# 使用独立 cleaner 角色；持续运行时内置每小时定时清理。
platform-audit cleanup --config config.toml --once
platform-audit cleanup --config config.toml

# 使用 reader 角色。默认及最大导出范围为最近30天（接收时间）。
platform-audit export --config config.toml --platform jobscheduler
platform-audit export --config config.toml --since 2026-09-23T00:00:00Z

# 可选 GitHub 关联，仅读时查询已批准仓库，GITHUB_TOKEN 从环境读取。
platform-audit export --config config.toml --github
```

GitHub 只按事件已有的 `repository + full commit` 查关联 PR，不会把 PR 作者当操作者；没有相关 PR 就保留无关联。只有 deployment UUID 而没有 repo/commit 的事件保留该引用，本版本不偷偷扩大 Coolify 凭证读取范围去补元数据。每次导出有有界缓存与 API 超时，授权仓库在 `github_repositories` 配置。

## 桶与角色准备

这是新建的独立归档资源，不应直接对共享应用桶套用配置。Object Lock 的 COMPLIANCE 保留期不能缩短；将具体桶、服务和生产动作纳入发布审核后再执行存储配置。

准备支持 Object Lock 的版本化桶，再应用 `policies/object-lock.json`（COMPLIANCE / 30 Days）和 `policies/lifecycle.json`。AWS CLI 对应的是 `create-bucket --object-lock-enabled-for-bucket`、`put-object-lock-configuration`、`put-bucket-lifecycle-configuration`；区域和兼容服务参数由运维按实际目标提供。服务本身**不会创建桶、修改锁/策略或提升权限**。

将 `policies/*.json` 中 `AUDIT_BUCKET` 替换成实际桶名；如果改变 prefix，同步修改 IAM 和生命周期范围。

| 角色 | 权限 |
|---|---|
| writer | PutObject/PutObjectRetention + 校验元数据/锁；显式拒绝删除、绕过保护和修改桶设置 |
| cleaner | 仅专用 prefix 列版本、读取期限/元数据、删除已到期版本；不能写日志、缩短锁或创建 delete marker |
| reader | 列版本和读取已存在版本，无写入/删除权限 |

分角色部署不同凭证；不要给 collector 管理员/桶所有者凭证。提供的是 S3 IAM 模板；具体提供商 IAM 语义仍须部署时验证。本地真实测试用隔离 MinIO 的管理员证明 COMPLIANCE 在 API 层也拒绝提前删除，并不声称已在用户生产 IAM 上验过这些策略。

## 独立部署

`compose.yaml` 只启动 audit collector 和 retention，不改原有 SigNoz Compose，也没有对外监听端口。两个进程使用不同凭证和持久化卷，不能互相访问对方的队列/清理状态。

1. 按现有日志卷/宿主机文件映射确认日志落点，挂成 `/sources/{platform}/...` **只读**；不要挂 Docker socket 或整个宿主机。不要为初次试用重启生产代理开启日志。不存在的来源会报告 `unavailable`，不能算接入成功。
2. `AUDIT_SOURCE_DIR` 是新采集服务的日志挂载根。来源日志权限应给必要读取权限，不用 chmod 777。运行 UID/GID 为 10001；已有主机日志组若需要，使用受控的 supplementary group 配置。
3. `AUDIT_WRITER_CREDENTIALS_FILE` / `AUDIT_CLEANER_CREDENTIALS_FILE` 指向各自标准 AWS credentials 文件，作为只读 secret。确保部署平台将它们提供给 UID 10001 且不对其他用户可读；Compose 文件型 secrets 的 UID/mode 行为需在目标宿主机核实。
4. 状态目录必须由进程 UID 拥有且不可由 group/other 写。首次 named volume 从镜像的 `/state` 初始化；复用错误权限卷会拒绝启动，不自动放宽权限。
5. 启动 `docker compose up -d --build` 后检查原生日志→archive→export，以及未知 actor、所有平台的缺源计数和清理状态。此步骤是未来审核后的部署步骤，本 PR 没有执行生产部署。

## 可选 SigNoz 检索副本

配置 `[index]` 为实际 OTLP HTTP `/v1/logs` 入口后，归档成功才发送可搜索副本，resource `service.name=internal-platform-audit`。`AUDIT_OTLP_TOKEN` 如需则从环境提供；现有内网 HTTP collector 必须明确配置 `allow_http=true`，不自动降级。

**默认关闭。** 启用前核实目的端 TTL 不超过 30 天，再填 `retention_confirmed_days`。该字段是部署时核实结果，不会自动更改/证明 SigNoz 的 TTL；不要为了本日志改变其他同事所需的全局保留期。没有独立或兼容 TTL 时继续使用归档查询。

索引不可用/部分拒收会记录 `index_failed_archive_retained`，归档及其他操作照常。可使用 `platform-audit reindex --config config.toml --since ...` 从归档补录；查询副本可能重复，按 `audit.event_id` 去重。查询副本可以删除，但受锁归档依然保留至到期；不要把副本当唯一证据。

## 验证与运行关注项

```sh
ruff format --check src tests
ruff check src tests --select E9,F63,F7,F82,F401
python -m pytest -q
```

真实对象锁测试需要专用 loopback S3 服务，设置 `AUDIT_TEST_S3_ENDPOINT` 和临时测试凭证。测试拒绝云/非 loopback 地址，自动创建 `audit-it-*` 隔离桶。未提供时明确 skip，不冒充完整集成通过。测试中短期过期对象仅是模拟到期状态，不声称等待过 30 个真实日历日。锁定的测试对象只能等期限或销毁其专用本机测试实例；绝不能清理共享/生产桶。

CI 使用临时 MinIO、合成日志/凭证，验证归档、未知用户、脱敏、提前删除拒绝、缩短保留拒绝、版本幂等、到期清理、存储故障恢复和索引故障不影响归档，并构建镜像。

运行时关注：`unavailable`、`oversized`、`truncations`、`collection_failed`、`archive_failed`、`expired_unarchived_events`、`index_failed_archive_retained`、`cleanup_failed`、`retention_sweep.blocked`。日志失败不得解释成没有操作；权限/扩展锁/法律保留异常需要运维处理。

部署前仍需验证：三个来源的真实挂载和格式/覆盖、WORM桶及分角色 IAM、目标资源预算、源日志轮转、目的索引 TTL。Coolify 原生未打点的 UI 语义、SigNoz 缺 method 的请求、来源采集前被删除的日志不在本版完整语义审计保证之内；这些限制明确写在事件类型和接入清单中。
