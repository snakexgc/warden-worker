# Vaultwarden 文件级实现对齐矩阵

参考提交：`D:\gitrepo\vaultwarden` @ `2629bcbe1380c894e3a7f52cafcac3988edb8fbb`

本报告按“上游文件职责”核对，不把 Axum/Workers 与 Rocket/原生服务器的框架差异误判为业务缺失。

| 上游文件/目录 | 本项目对应文件 | 本轮结果 | Workers 差异位置 |
| --- | --- | --- | --- |
| `api/core/accounts.rs` | `api/core/accounts.rs` | API Key 生成逻辑复用并保持现有注册/密钥登录 | `accounts/devices.rs`、通知扩展 |
| `api/core/ciphers.rs` | `api/core/ciphers.rs` | 补齐 admin/share/delete/restore 单项及批量方法 | HeavyDo 路由 |
| `api/core/ciphers.rs` 附件职责 | `ciphers/attachments.rs` | 组织附件、share/admin/delete-admin 均补齐 | R2 存储实现 |
| `api/core/organizations.rs` | `api/core/organizations.rs` | 77 个规范化方法均有路由；API Key 与 SSO verified 补齐 | D1 权限 SQL、通知扩展 |
| `api/core/public.rs` | `api/core/public.rs` | Directory Connector Public API 导入已实现 | D1 批处理、通知 outbox |
| `api/core/emergency_access.rs` | `api/core/emergency_access.rs` | 18 个方法全部实现，含 Cron 自动批准 | D1 状态表、`lib.rs` Cron |
| `db/models/emergency_access.rs` | `db/models/emergency_access.rs` | 类型、状态与 JSON 基础模型已对齐 | D1 SQL 在 API/helper 中执行 |
| `api/core/two_factor/duo.rs` | `api/core/two_factor/duo.rs` | 3 个管理方法及登录签名验证已实现 | Workers fetch；Duo OIDC 未迁移 |
| `api/core/two_factor/yubikey.rs` | `api/core/two_factor/yubikey.rs` | 3 个管理方法及 OTP 登录验证已实现 | Workers fetch |
| `api/identity.rs` | `api/identity.rs` | 组织 client credentials、Duo/Yubi provider 登录进入统一 token 链 | 边缘 JWT、Passkey/Auth Request 保留 |
| `db/models/two_factor.rs` | `db/models/two_factor.rs` | 外部 provider 持久化、状态、删除/恢复清理补齐 | `two_factor_external` D1 表 |
| `api/core/sends.rs` | `api/core/sends.rs` | 上游职责保持，未被组织改造覆盖 | Turnstile 人机验证、R2 文件分片保留 |
| `api/core/two_factor/webauthn.rs` | 同名文件 | 未改写原有能力 | Passkey/密钥登录与 Workers WebAuthn runtime 保留 |
| `api/notifications.rs` | 同名文件 | 组织/附件变更继续复用实时广播 | Webhook/Telegram/企业微信位于 `extensions/notify` |

## 数据迁移

| migration | 目的 | 验证 |
| --- | --- | --- |
| `0002_organization_api_key_compat.sql` | 对齐组织 API Key 列名 | 通过 |
| `0003_organization_attachments.sql` | 允许组织附件无个人 owner | 通过 |
| `0004_emergency_access.sql` | 紧急访问状态与关系 | 通过 |
| `0005_external_two_factor.sql` | Duo/YubiKey provider 数据 | 通过 |

## 方法级结果

- 紧急访问及 Duo/YubiKey：上游 24 个方法，匹配 24 个，缺失 0。
- 全部 Vaultwarden core：机械提取 252 个方法；唯一前缀表面差异为 `events.rs` 的 `/collect` 挂载，本项目实际已有 `/events/collect`。
- Worker 额外路由继续存在，用于 Turnstile、Passkey、D1 usage、R2 上传和兼容别名。

## 仍需后续文件迁移

- Enterprise SSO/SCIM/Provider 相关独立模块。
- Duo OIDC 流程；当前实现与 Vaultwarden 的 legacy iframe 签名流程一致。
- 全部组织服务端 audit event 副作用及策略的端到端语义回归。
