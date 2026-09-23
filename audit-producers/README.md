# 平台端操作日志接入（待发布）

这部分是日志的**产生端**，对应独立归档服务 PR #6。仅安装归档后台无法补出原平台没有记录的动作。这里给当前实际使用的第三方版本添加源码补丁、真实运行时测试和可构建镜像，不创建或部署生产资源。

| 平台 | 已核对上游 | 新记录 |
|---|---|---|
| Coolify | 4.3.23 / e2e2d4010bcd590084b66d6f748f3eec8e2bbee9 | Livewire 方法调用/返回；列明模型的创建/保存/删除；部署编号、GitHub 仓库及已解析的 commit |
| SigNoz | v0.97.1 enterprise / 416e8d2a5eb1278666b9e67a4cddcbaead61bdc5 | 仪表盘、告警规则、通知渠道、用户/组织、保留期、日志 pipeline 等修改请求的方法、路由模板、对象 ID、状态及可核实账号 |
| JobScheduler | master f3d80d9ffbf14d0ea4e99508f3d813cd4c0f533e | 由 jobscheduler 仓库的操作日志 PR 实现 HTML/OpenPlatform 业务事件；本目录不复制业务服务 |

## 行为和边界

- 沿用原页面、权限和认证。Coolify 复用原生 fail-open auditLog，IP 使用 socket peer；记录 Livewire 服务端组件/方法，参数、配置值、环境变量值不写日志。模型记录只含字段名；事务内保存标为 `transaction_pending`，不能据此宣称已提交。批量 SQL、直接数据库操作、未列入模型表的业务不属于模型事件覆盖范围。
- Livewire `called/returned` 表示调用/返回，不能将内部吞掉的业务错误写成成功。普通轮询方法被过滤。部署请求、解析 commit 和部署状态事件共享 deployment UUID；HEAD 尚未解析时不伪造 SHA。后台部署状态事件没有人类 actor。
- SigNoz 在现有认证之后捕获可信 claims。JWT 账号为 platform_user；API Key 只知道所有者时为 api_credential_owner。匿名/认证失败时允许 actor=null。POST 不自动叫“创建”，HTTP 2xx 不等于后续任务完成。新建对象的 ID 未出现在路径时为 null，不读取响应或请求体来凑 ID。
- SigNoz 保留既有 EE 入口、前端及模板；补丁重新编译后端。操作路由 allowlist 明列在 `operation_audit.go`，不包括高频只读 query_range/history/preview；未列入的自定义路由需补充。队列上限 1024，满时丢弃并在后续记录累计 dropped 计数，不阻塞请求。
- 本地文件/内存队列不是防删归档；进程被杀、队列溢出、未及时采集的文件轮转仍可丢失。30 天 COMPLIANCE 防删保护在 PR #6 上传确认后生效。保留平台正常使用与绝不丢审计无法同时承诺，本版选择 fail-open。
- 不增加库表，不改变 prod/test 业务字段，不把代码作者推断成操作人。

## 构建及发布材料

```sh
# 在此仓库根目录执行；prepare 拒绝已有目标目录，校验固定提交和补丁 hash。
python3 audit-producers/prepare.py signoz audit-producers/signoz/source
docker build -t signoz-audit:v0.97.1-audit.1 audit-producers/signoz
docker build -t coolify-audit:4.3.23-audit.1 audit-producers/coolify
```

Coolify 构建先验证官方镜像内三个修改文件的 SHA256，再应用补丁；版本漂移直接失败。CI 对上游源码执行 apply --check，并在官方运行时依赖中测试 Livewire hook、真实 Eloquent SQLite save/delete、事务未提交标记和日志失败隔离。SigNoz 执行中间件 race 测试、完整 enterprise 二进制构建和 version 启动检查。CI 不推送镜像、不连接生产、不触发部署。

`coolify/compose.override.yaml`、`signoz/compose.override.yaml` 是实际可合并的发布覆盖文件。发布须先在隔离实例验证，使用已测试镜像 digest，再对已确认的生产 Compose 合并；保留原镜像 digest 即可回滚。Coolify 发布前要复制/保留现有 storage/logs 并创建 UID/GID 9999 可写的 `/data/platform-audit/coolify`（不可直接挂载空目录遮掉旧日志）；本轮没有执行这些动作。LOG_AUDIT_DAYS=30 是本地滚动上限，独立归档由原 PR 的专用清理权限按接收时间清理。

## 接到归档

- Coolify：只读挂载 `/data/platform-audit/coolify` 至 collector 的 `/sources/coolify`，匹配 audit*.log；不要把整个应用目录或 Docker socket 交给 collector。
- JobScheduler、SigNoz：新事件输出至现有容器日志。由宿主机管理的日志采集将对应容器日志目录只读提供给 collector。按实例 UUID/容器日志路径锁定来源，保留 Docker JSON time envelope；切换容器后更新挂载，不能凭模糊容器名匹配。
- 三个来源分属不同主机时，在各主机放一个只读 collector，使用唯一 source ID，共用独立 bucket 前缀；不要把 Docker socket 暴露到网络。清理任务只需一个独立实例。
- 先部署 PR #6 的新增 producer schema 解析，再启用生产端镜像。验收必须做一笔经授权的测试操作，检查 operation/deployment ID 从平台输出到对象锁归档能贯通；本轮只在隔离测试运行，没有线上操作验收。

尚未核实生产镜像替换、日志目录 UID/ACL、归档 bucket 和跨主机挂载；这些是待发布条件，不能据本 PR 声称线上已覆盖。

配套业务端：[JobScheduler PR #5](https://github.com/ANIMO-TECH/jobscheduler/pull/5)。
