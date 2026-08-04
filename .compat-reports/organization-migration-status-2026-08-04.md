# Warden Worker 组织功能迁移状态

审计日期：2026-08-04

对比基线：

- Warden Worker：`d89466593dd4c799cb9a311ff65211fb7f927dc8` 加当前未提交实现
- Vaultwarden：`2629bcbe1380c894e3a7f52cafcac3988edb8fbb`
- Vaultwarden 组织端点基线：`src/api/core/organizations.rs`

## 结论

组织核心功能能够在 Cloudflare Workers、D1、R2 和 Durable Objects 上实现。当前工作树已经完成可试运行的组织核心链路，但尚未达到 Vaultwarden 全量组织/企业能力的语义等价，因此 `ORGANIZATIONS_ENABLED` 默认保持为 `false`。

对 Vaultwarden `organizations.rs` 的 77 个规范化方法-路径组合进行机械比对后，当前路由已覆盖 74 个，剩余 3 个：

- `POST /api/organizations/domain/sso/verified`：SSO 未实现。
- `POST /api/organizations/{id}/api-key`：组织 API Key 未实现。
- `POST /api/organizations/{id}/rotate-api-key`：组织 API Key 轮换未实现。

路由存在只表示客户端不会因缺少路径而失败，不代表响应字段、权限副作用和并发行为已经逐项完全等价。

## 已实现

| 能力 | 当前状态 | Workers 实现方式 |
| --- | --- | --- |
| 多用户与注册 | 已实现 | 移除单用户触发器；一次性注册/邀请 JWT；Webhook/Telegram outbox 与 Cron 重试 |
| 组织 CRUD | 已实现 | D1 `organizations`、`users_organizations`；Owner/Admin/Manager 守卫 |
| 成员邀请与管理 | 已实现 | 邀请、接受、确认、重发、编辑、吊销、恢复、删除及批量端点；最后一个 Owner 由原子条件写保护 |
| 账户恢复 | 已实现核心流程 | Reset Password 策略、用户自助加入/退出、管理员恢复、security stamp 登出 |
| 集合与授权 | 已实现 | 直接成员授权、组授权、`accessAll/readOnly/hidePasswords/manage` |
| 共享密码项 | 已实现核心流程 | 个人与组织密码项统一鉴权查询；集合分配；按用户收藏、文件夹和归档 |
| Sync/Profile | 已实现 | 返回组织、集合、策略和当前用户可访问的共享密码项 |
| 组织导入/导出 | 已实现核心流程 | D1 每批 40 条；导入上限 500 个密码项/集合；导出组织集合和密码项 |
| 策略 | 部分实现 | 2FA、Single Organization、Disable Send、Send Options、Account Recovery 已进入业务判断 |
| 组 | 已实现核心 CRUD/授权 | 默认由 `ORG_GROUPS_ENABLED=false` 关闭 |
| 事件 | 已实现客户端采集与查询 | D1 持久化、组织/成员/密码项分页查询；默认关闭 |
| 实时同步 | 已实现核心广播 | 组织密码项变更向所有已确认成员广播；HeavyDo 按身份稳定分片 |

## 仍需补齐或强化

1. 组织密码项附件：当前会安全拒绝，不能复用个人附件的 `user_id` 权限模型。
2. 组织 API Key 和 `scope=api.organization` 客户端凭据登录。
3. SSO、SCIM、Provider、Directory Connector/Public API 等企业集成。
4. 服务端组织操作事件：当前可保存客户端上报事件，但大部分组织 mutation 尚未自动生成审计事件。
5. 策略完整语义：Master Password、Remove Individual Vault、Organization Data Ownership 等仍需逐端点接入。
6. 大型导入原子性：D1 跨批请求不是一个事务，失败时可能已写入前面的批次；需增加导入作业状态和补偿清理。
7. Groups/Events 的端到端 Web Vault 回归尚未完成，因此两个开关默认关闭。

## 已验证

- `cargo test --lib`：67/67 通过。
- `node --test tests/heavy_do_routing.test.mjs`：4/4 通过。
- `cargo clippy --target wasm32-unknown-unknown -- -D warnings`：通过。
- `cargo check --target wasm32-unknown-unknown`：通过。
- D1 基线加 `0001_organization_core.sql`：本地迁移成功，外键检查无错误。
- D1 权限样例：普通成员加入 `groups.access_all=1` 的组后，可以读取组织全部集合，并得到可写和可查看密码权限。
- D1 Owner 保护样例：删除唯一 confirmed Owner 的条件写影响 0 行，Owner 记录保持不变。

## 启用顺序

1. 备份 D1/R2。
2. 执行 `wrangler d1 migrations apply vaultsql --remote`。
3. 配置并验证 Webhook/Telegram 注册与邀请链接投递。
4. 在测试环境设置 `ORGANIZATIONS_ENABLED=true`，完成双用户创建、邀请、确认、同步和共享密码项回归。
5. 核心流程稳定后再分别启用 `ORG_GROUPS_ENABLED` 与 `ORG_EVENTS_ENABLED`。
