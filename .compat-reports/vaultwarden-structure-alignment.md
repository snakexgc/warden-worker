# Vaultwarden 文件结构对齐规则

对比基线：`D:\gitrepo\vaultwarden`。

## 目标结构

```text
src/
  api/
    mod.rs
    core/
      mod.rs
      accounts.rs
      attachments.rs
      ciphers.rs
      devices.rs
      events.rs
      folders.rs
      import.rs
      organizations.rs
      sends.rs
      two_factor.rs
      ...
    icons.rs
    identity.rs
    notifications.rs
    router.rs
    web.rs
  db/
    mod.rs
    models/
      mod.rs
      archive.rs
      attachment.rs
      cipher.rs
      collection.rs
      event.rs
      folder.rs
      group.rs
      organization.rs
      org_policy.rs
      send.rs
      two_factor.rs
      user.rs
      ...
  extensions/
    notify/
      ...
  worker_runtime/
    ...
```

## 映射原则

1. Vaultwarden `src/api/core/*.rs` 对应客户端业务端点；原 `src/handlers` 不再作为长期目录存在。
2. Vaultwarden `src/db/models/*.rs` 对应 D1 实体与关系；原 `src/models` 不再作为长期目录存在。
3. `identity`、`icons`、`notifications` 保持在 `src/api` 顶层，与 Vaultwarden 一致。
4. Axum 路由装配保留为 `src/api/router.rs`，因为 Vaultwarden 使用 Rocket route 列表，而 Workers 需要单一 Router。
5. Webhook/Telegram/outbox 属于本项目扩展，放入 `src/extensions/notify`，不混入 Vaultwarden 的实时通知模块。
6. HeavyDo、Workers 入口、R2、D1 密钥管理和后台执行器属于平台适配层，放入 `src/worker_runtime`。
7. 与 Vaultwarden 同名的业务文件优先保持端点、DTO 和权限逻辑在相同位置；平台适配通过独立模块调用。
8. 每次结构迁移必须保持 `cargo check --target wasm32-unknown-unknown` 通过，再进入下一层拆分。

## 第一阶段文件映射

| 当前文件 | 目标文件 |
| --- | --- |
| `src/handlers/accounts.rs` | `src/api/core/accounts.rs` |
| `src/handlers/ciphers.rs` | `src/api/core/ciphers.rs` |
| `src/handlers/events.rs` | `src/api/core/events.rs` |
| `src/handlers/folders.rs` | `src/api/core/folders.rs` |
| `src/handlers/organizations.rs` | `src/api/core/organizations.rs` |
| `src/handlers/sends.rs` | `src/api/core/sends.rs` |
| `src/handlers/two_factor.rs` | `src/api/core/two_factor.rs` |
| 其余业务 handler | `src/api/core/<name>.rs` |
| `src/handlers/identity.rs` | `src/api/identity.rs` |
| `src/handlers/icons.rs` | `src/api/icons.rs` |
| `src/notifications.rs` | `src/api/notifications.rs` |
| `src/router.rs` | `src/api/router.rs` |
| `src/db.rs` | `src/db/mod.rs` |
| `src/models/*` | `src/db/models/*` |

## 执行结果

本轮以 Vaultwarden `2629bcbe1380c894e3a7f52cafcac3988edb8fbb` 为结构参照，已完成：

- HTTP 业务代码迁移到 `src/api/core`，API 顶层模块迁移到 `src/api`。
- D1 入口迁移到 `src/db/mod.rs`，数据模型及两步验证持久化操作迁移到 `src/db/models`。
- `Attachment`、`Event`、`Collection`、`Group`、`OrgPolicy` 和两步验证持久化逻辑归入 Vaultwarden 同名模型文件。
- Webhook、Telegram、企业微信及 outbox 迁移到 `src/extensions/notify`。
- Durable Object、后台任务、R2、日志以及 D1 密钥管理迁移到 `src/worker_runtime`。
- 历史审计文档和维护记录中的源码路径已同步更新。

## 有意保留的结构差异

- `src/api/router.rs`：Vaultwarden 使用 Rocket route 列表，本项目使用 Axum，因此保留独立装配文件。
- `src/api/core/attachments.rs`、`devices.rs`、`import.rs`、`settings.rs`、`sync.rs` 等：这些端点在 Vaultwarden 中分布于较大的模块；本项目继续按 Axum handler 边界拆分，防止为了文件名一致而合并无关实现。
- `src/entry.js` 与 `src/heavy_do_routing.mjs`：Wrangler 直接使用的 JavaScript 入口和路由规则，必须保留在可独立测试的位置。
- `src/extensions` 和 `src/worker_runtime`：仅承载本项目特有功能；后续同步 Vaultwarden 时不应把这些实现反向混入同名核心模块。

后续迁移应优先比较 `src/api` 与 `src/db/models` 中的同名文件；平台差异只通过 `src/extensions` 或 `src/worker_runtime` 暴露的窄接口接入。
