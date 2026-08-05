# Vaultwarden 文件级结构对齐

参考仓库：`D:\gitrepo\vaultwarden`

参考提交：`2629bcbe1380c894e3a7f52cafcac3988edb8fbb`

参考仓库在本次工作中只读使用；所有移动、重构和测试均在 `D:\gitrepo\warden-worker` 完成。

## 当前结构

```text
src/
  api/
    mod.rs
    core/
      mod.rs
      accounts.rs
      accounts/devices.rs
      ciphers.rs
      ciphers/attachments.rs
      ciphers/sync.rs
      ciphers/sync/models.rs
      emergency_access.rs
      events.rs
      folders.rs
      imports.rs
      imports/models.rs
      meta/{mod.rs,config.rs,hibp.rs,settings.rs}
      organizations.rs
      public.rs
      sends.rs
      two_factor/{authenticator.rs,duo.rs,duo_oidc.rs,email.rs,mod.rs,protected_actions.rs,webauthn.rs,yubikey.rs}
    icons.rs
    identity.rs
    notifications.rs
    push.rs
    web.rs
  db/
    mod.rs
    models/
      archive.rs
      attachment.rs
      auth_request.rs
      cipher.rs
      collection.rs
      device.rs
      emergency_access.rs
      event.rs
      favorite.rs
      folder.rs
      group.rs
      org_policy.rs
      organization.rs
      send.rs
      two_factor.rs
      two_factor_duo_context.rs
      two_factor_incomplete.rs
      user.rs
  crypto/
    password.rs
  extensions/
    notify/
    usage.rs
  worker_runtime/
    background.rs
    domains.rs
    heavy_do.rs
    jwt.rs
    jwt_manager.rs
    logging.rs
    r2_file.rs
    router.rs
    two_factor_key_manager.rs
    webauthn.rs
```

## 文件职责映射

| Vaultwarden 文件 | Warden Worker 主文件 | Workers 补充文件 | 状态 |
| --- | --- | --- | --- |
| `api/core/accounts.rs` | `api/core/accounts.rs` | `accounts/devices.rs` | 设备与 AuthRequest 端点由 accounts 对外暴露 |
| `api/core/ciphers.rs` | `api/core/ciphers.rs` | `ciphers/attachments.rs`、`ciphers/sync.rs` | 附件、同步、个人导入由 ciphers 对外暴露 |
| `api/core/events.rs` | `api/core/events.rs` | 无 | 同名职责 |
| `api/core/emergency_access.rs` | `api/core/emergency_access.rs` | `lib.rs` Cron | 邀请、状态机、查看与接管职责同名 |
| `api/core/folders.rs` | `api/core/folders.rs` | 无 | 同名职责 |
| `api/core/organizations.rs` | `api/core/organizations.rs` | `imports.rs` 中的共享 D1 批处理 | 组织导入由 organizations 对外暴露 |
| `api/core/public.rs` | `api/core/public.rs` | `extensions/notify/*` | Directory Connector 导入与邀请投递分离 |
| `api/core/sends.rs` | `api/core/sends.rs` | `worker_runtime/r2_file.rs` | 同名业务职责，R2 流式存储已隔离 |
| `api/core/two_factor/mod.rs` | `api/core/two_factor/mod.rs` | `worker_runtime/webauthn.rs` | 2FA 模块层级一致 |
| `api/core/two_factor/webauthn.rs` | `api/core/two_factor/webauthn.rs` | `worker_runtime/webauthn.rs` | 端点与 Workers 协议实现分离 |
| `api/core/two_factor/duo.rs` | `api/core/two_factor/duo.rs` | 无 | Auth API 与旧版签名流程使用 Workers fetch |
| `api/core/two_factor/duo_oidc.rs` | `api/core/two_factor/duo_oidc.rs` | `lib.rs` Cron | Universal Prompt 使用 Workers fetch，state/nonce 存入 D1 |
| `api/core/two_factor/authenticator.rs` | 同名文件 | 无 | TOTP 管理端点从公共模块拆出 |
| `api/core/two_factor/email.rs` | 同名文件 | `extensions/notify/*` | Email 2FA 端点保留 Auth Request/密钥登录兼容 |
| `api/core/two_factor/protected_actions.rs` | 同名文件 | 无 | 受保护操作 OTP 从 accounts 拆出 |
| `api/core/two_factor/yubikey.rs` | `api/core/two_factor/yubikey.rs` | 无 | Yubico OTP 2.0 请求和响应签名校验 |
| `api/core/mod.rs` | `api/core/mod.rs` | `meta/*` | config、domains、HIBP、alive 等由 core 统一导出 |
| `api/identity.rs` | `api/identity.rs` | `worker_runtime/jwt.rs` | 身份端点保持同名，边缘 JWT 实现隔离 |
| `api/icons.rs` | `api/icons.rs` | 无 | 同名职责 |
| `api/notifications.rs` | `api/notifications.rs` | `extensions/notify/*` | 实时通知与 Webhook/Telegram 分离 |
| `api/push.rs` | `api/push.rs` | `api/notifications.rs` | Bitwarden Push Relay 使用 Workers fetch，并复用现有实时通知调用点 |
| `api/web.rs` | `api/web.rs` | `entry.js`、Workers Assets | 静态资源由 Cloudflare Assets 接管 |

## 模型边界

- `Attachment`、`AuthRequest`、`Device`、`Event`、`Collection`、`Group`、`OrgPolicy`、`TwoFactor` 均有 Vaultwarden 同名模型文件。
- 导入请求和同步响应是 API DTO，已从 `db/models` 移至对应 API 辅助文件。
- 邀请令牌与注册验证令牌声明已从数据库模型移至 `auth.rs`，与 Vaultwarden 的 JWT claims 归属一致。
- `db/models` 只保留实体、关系、持久化数据和与实体紧密相关的序列化逻辑。

## 项目特有功能边界

- `src/extensions/notify`：Webhook、Telegram、企业微信、模板和 outbox。
- `src/extensions/usage.rs`：Cloudflare D1/R2 使用量接口。
- `src/worker_runtime`：Axum Router、Durable Object、R2、Workers 后台任务、远程 domains、边缘 JWT/WebAuthn 和 D1 密钥管理。
- `src/crypto/password.rs`：在 HeavyDo CPU 环境执行的服务端密码验证适配。
- `src/entry.js`、`src/heavy_do_routing.mjs`：Wrangler JavaScript 入口及 HeavyDo 路由规则。

## 有意保留的差异

- Vaultwarden 使用 Rocket、SQLite/MySQL/PostgreSQL 和文件系统；本项目使用 Axum、D1、R2 和 Durable Objects，框架装配不能逐行复用。
- `imports.rs`、`meta/*` 以及 accounts/ciphers 的子文件用于控制 Workers 单文件体积，但其公开职责由 Vaultwarden 对应主模块统一暴露。
- `emergency_access.rs`、`public.rs`、完整 two-factor 子文件和 `api/push.rs` 已按上游文件职责补入；SSO、SCIM、Provider、SMTP 与服务端 admin 页面仍不创建空实现。
- 后续同步上游时，优先比较同名主文件；任何平台差异必须进入 `extensions`、`worker_runtime` 或对应主文件的补充子模块。

## 维护约束

1. 不在 `D:\gitrepo\vaultwarden` 执行写操作。
2. 每个 Vaultwarden 端点优先归入相同主模块，不为 Axum 路由单独创建平级业务文件。
3. API DTO 不放入 `db/models`；JWT claims 不放入数据库实体。
4. 每次文件或 schema 对齐先运行 `cargo check --target wasm32-unknown-unknown`，完成后运行全部 Rust、Node 和 Clippy 检查。
5. D1 结构只在 `sql/schema.sql` 中维护；业务代码不得运行建表、补列或旧数据回填 SQL。

## 本次验证

- `cargo check --target wasm32-unknown-unknown`：通过。
- `cargo test --all-targets`：79 passed、0 failed。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/*.test.mjs`：24 passed、0 failed。
- `worker-build --release`：通过，生成 release Wasm 产物。
- `cargo fmt --all -- --check` 与 `git diff --check`：通过。
- 隔离本地 D1 完整基线：118 条语句执行成功，38 张表、41 个显式索引，`PRAGMA foreign_key_check` 无错误。
- 对齐前后 `D:\gitrepo\vaultwarden` 均保持提交 `2629bcbe1380c894e3a7f52cafcac3988edb8fbb`，工作树为空。
