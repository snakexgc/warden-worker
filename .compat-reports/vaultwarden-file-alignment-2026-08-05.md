# Vaultwarden 文件级对齐增量报告（2026-08-05）

参考仓库：`D:\gitrepo\vaultwarden` @ `2629bcbe1380c894e3a7f52cafcac3988edb8fbb`

本轮只读参考 Vaultwarden，在 Warden Worker 中完成同名文件迁移。Workers 专有实现继续保留在 `worker_runtime`、`extensions` 及 API 子文件中，未移除 Send Turnstile、Passkey/密钥登录、Webhook、Telegram、企业微信、D1、R2、Durable Object 或 HeavyDo。

## 已对齐文件

| Vaultwarden 文件 | 本项目结果 | Workers 适配 |
| --- | --- | --- |
| `api/core/two_factor/authenticator.rs` | 同名文件已拆分 | 继续使用 D1 加密 secret 与现有通知 |
| `api/core/two_factor/email.rs` | 同名文件已拆分 | 保留 Auth Request/密钥登录发码和 Webhook 邮件通道 |
| `api/core/two_factor/protected_actions.rs` | 同名文件已拆分 | 从 `accounts.rs` 移出，路由直接指向新模块 |
| `api/core/two_factor/duo_oidc.rs` | Duo Universal Prompt 已实现 | Fetch 调用 Duo OAuth API；state/nonce 使用 D1 一次性消费 |
| `api/push.rs` | 移动端 Push Relay 已实现 | Fetch 获取安装令牌、注册设备并发送更新；现有 Durable Object 广播不变 |
| `db/models/favorite.rs` | 同名 D1 模型已补齐 | 批量密码项操作仍保留原子 D1 batch SQL |
| `db/models/two_factor_incomplete.rs` | 同名模型及 Cron 已补齐 | 超时事件投递到已有 Webhook/Telegram/企业微信通道 |
| `db/models/two_factor_duo_context.rs` | 同名模型已补齐 | `DELETE ... RETURNING` 原子消费 state，防止回放 |
| `db/models/device.rs` | Push 字段与设备 token API 已补齐 | D1 模型只负责数据映射，结构直接定义在完整基线中 |

## 数据库基线收敛

| 原增量结构 | 合入基线后的结果 | 本地 D1 结果 |
| --- | --- | --- |
| 组织、成员、集合、组、策略、事件 | 直接由 `sql/schema.sql` 创建 | 通过 |
| 紧急访问、外部 2FA、未完成 2FA、Duo context | 直接由 `sql/schema.sql` 创建 | 通过 |
| 组织附件语义与设备 Push 字段 | `cipher_attachments.user_id` 可空；`devices` 直接包含 Push 字段 | 通过 |

当前分支不再维护增量迁移或旧数据库升级路径。原 `0001` 至 `0008` 的最终结构全部合入 `sql/schema.sql`，`sql/migrations` 已删除；Worker 运行时也不再执行建表、补列或旧数据回填。完整基线在隔离的本地 D1 中执行 118 条语句成功，共创建 38 张业务表和 41 个显式索引，`PRAGMA foreign_key_check` 无错误。

服务端用户密码和 Send 密码只接受当前 Vaultwarden 风格的 PBKDF2 记录，不再回退读取本项目旧设计的哈希格式。Vaultwarden 仍保留的客户端版本兼容路由、Duo Traditional Prompt 开关和旧版附件/Send API 路径不属于数据库升级补丁，继续保留。

## 行为边界

- Duo 默认与 Vaultwarden 一致使用 Universal Prompt；设置 `DUO_USE_IFRAME=true` 可保留旧 Traditional Prompt，旧流额外需要 `DUO_AKEY`。
- Push 默认关闭，仅在 `PUSH_ENABLED=true` 且安装 ID/Key 配齐时访问外部服务。组织密码项不发送移动 Push，与 Vaultwarden 当前限制一致。
- 未完成 2FA 告警仅在通知通道已配置且等待时间大于 0 时记录和处理；成功完成 2FA 后立即删除记录。

## 尚未补齐的上游独立文件

- `api/admin.rs`：Vaultwarden 的服务端管理页面和配置管理；不能直接复用到 Workers，需单独设计边缘鉴权与静态 UI。
- `db/models/sso_auth.rs`、根目录 `sso.rs`、`sso_client.rs`：OIDC 本身可由 Workers Fetch/JWT/D1 实现，但需要一次性迁移完整登录、刷新、会话撤销和组织 SSO 绑定语义，当前仅保留客户端占位兼容，不宣称支持 SSO。
- SCIM、Provider 与 SMTP 仍属于后续独立能力；Webhook/Telegram/企业微信注册及通知是本项目保留扩展，不应塞回 Vaultwarden 同名文件。

## 验证结果

- `cargo check --target wasm32-unknown-unknown`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `cargo test --all-targets`：79 passed，0 failed。
- `node --test tests/*.test.mjs`：24 passed，0 failed。
- `worker-build --release`：通过，生成 release Wasm 产物。
- 隔离本地 D1 完整基线：118 条语句执行成功，38 张表、41 个显式索引，外键检查无错误。
