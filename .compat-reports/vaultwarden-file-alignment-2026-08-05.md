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
| `db/models/device.rs` | Push 字段与设备 token API 已补齐 | `push_token/push_uuid` 由迁移加入 D1 |

## 数据迁移

| migration | 目的 | 本地 D1 结果 |
| --- | --- | --- |
| `0006_two_factor_incomplete.sql` | 未完成二步验证登录记录 | 通过 |
| `0007_two_factor_duo_context.sql` | Duo OIDC state/nonce | 通过；一次性 `DELETE ... RETURNING` 实测通过 |
| `0008_device_push.sql` | 移动设备 Push token/relay UUID | 通过 |

基线 `sql/schema.sql` 没有回填这些增量结构，符合仓库“基线后只新增 migration”的部署约束。完整基线加 `0001` 至 `0008` 已顺序应用，`PRAGMA foreign_key_check` 无错误。

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
- `cargo test --lib`：80 passed，0 failed。
- `node --test tests/*.test.mjs`：22 passed，0 failed。
- `worker-build --release`：通过，生成 release Wasm 产物。
- D1 基线加 `0001` 至 `0008`：通过，新增表、列和索引已核验。
