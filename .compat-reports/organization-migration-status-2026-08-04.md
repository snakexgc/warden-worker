# Warden Worker 组织功能迁移状态

审计日期：2026-08-04

对比基线：

- Warden Worker 分支：`agent/organization-management-migration`
- 本轮开始提交：`53c2376239a6f730cf9764abcb5fa42495e05924`
- Vaultwarden：`2629bcbe1380c894e3a7f52cafcac3988edb8fbb`

## 当前结论

Vaultwarden core 的组织管理、组织密码项/附件、Public Directory Connector 导入、组织 API Key、紧急访问，以及 Duo/YubiKey 管理与登录端点，已经在 Workers 架构中形成可执行实现。

方法级机械审计覆盖 Vaultwarden core 的 252 个方法-路径注册。本项目唯一未直接按 `/api` 前缀匹配的记录是上游 `events.rs` 中的 `POST /collect`；它在 Vaultwarden 由 `/events` 挂载，在本项目对应已有的 `POST /events/collect`，不是功能缺失。

路由存在不等于所有企业能力语义完全等价。SSO、SCIM、Provider、Duo OIDC 等独立企业集成仍不在当前迁移范围内，因此 `ORGANIZATIONS_ENABLED`、`ORG_GROUPS_ENABLED`、`ORG_EVENTS_ENABLED` 继续默认关闭，待端到端环境回归后再开启。

## 已补齐

| 能力 | 状态 | Workers 实现 |
| --- | --- | --- |
| 多用户与组织 CRUD | 已实现 | D1 成员、角色、状态、最后 Owner 保护 |
| 邀请/确认/撤销/恢复 | 已实现 | JWT 邀请；Webhook/Telegram/企业微信 outbox 投递 |
| Collection/Group 授权 | 已实现 | 直接成员与组授权；`accessAll/readOnly/hidePasswords/manage` |
| 组织密码项 | 已实现 | admin/share/delete/restore/bulk 别名与成员广播 |
| 组织附件 | 已实现 | 父密码项鉴权；D1 可空 owner；R2 organization scope |
| Sync/Profile/Policy | 已实现核心语义 | 组织、集合、策略、共享密码项进入同步结果 |
| 组织导入/导出 | 已实现 | Web Vault 导入和 Public Directory Connector 导入 |
| 组织 API Key | 已实现 | 生成/轮换及 `scope=api.organization` client credentials |
| 紧急访问 | 已实现 | 邀请、确认、等待、批准、查看、接管、策略与 Cron 推进 |
| Duo/YubiKey OTP | 已实现 | Workers fetch 外部校验、D1 配置和登录 provider 链 |

## 有意保留的项目扩展

- Send 的 Turnstile 人机验证及其签名访问凭证。
- Passkey/WebAuthn 密钥登录和本项目已有的 Auth Request 登录。
- Webhook、Telegram Bot、企业微信、通知 outbox 与 Cron 重试。
- Cloudflare D1、R2、Durable Objects、HeavyDo 分片及用量接口。

## 尚未宣称完全等价的范围

1. Enterprise SSO、SCIM、Provider、Duo OIDC 没有迁移；`domain/sso/verified` 仅保持 Vaultwarden 自托管兼容响应。
2. 组织 mutation 的服务端审计事件尚未逐个覆盖 Vaultwarden 的全部副作用。
3. Master Password、Remove Individual Vault、Organization Data Ownership 等策略仍需逐端点业务回归。
4. D1 跨批次的大型导入不是单一事务，需要部署环境中的失败恢复测试。
5. Duo/YubiKey 的协议与签名已有单元测试，但真实外部服务测试需要部署方 Secrets 和设备。

## 验证结果

- `cargo check --target wasm32-unknown-unknown`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `cargo test --lib`：76 passed、0 failed。
- `node --test tests/*.test.mjs`：22 passed、0 failed。
- D1 `schema.sql` + `0001` 至 `0005`：本地完整迁移通过。
- `PRAGMA foreign_key_check`：无异常。
- Vaultwarden 参考仓库仍为 `2629bcbe...`，工作树为空。

## 建议启用顺序

1. 备份 D1 与 R2，远端执行全部 migration。
2. 验证注册、组织邀请和紧急访问邀请均能通过现有通知通道送达。
3. 测试环境开启 `ORGANIZATIONS_ENABLED=true`，完成双用户组织、集合、共享密码项与附件回归。
4. 再分别开启 Groups、Events；配置外部服务 Secrets 后开启 Duo/YubiKey 的 Web Vault 入口。
