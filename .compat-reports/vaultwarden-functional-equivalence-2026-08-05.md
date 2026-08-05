# Warden Worker × Vaultwarden 逐文件功能等价确认报告

> 用途：回应"Beyond Compare 显示 src 存在巨大差异，疑似功能实现不一致 / 功能缺失 / 文件缺失"的质疑。
> 结论先行：**本仓库是 Vaultwarden 的协议级重写实现，不是代码级分支**。文本差异巨大是平台技术栈全换的必然结果，不能作为功能缺失的证据；但确实存在 5 个文件级缺失与 4 类有意的功能替换，本报告逐一定性。

审计日期：2026-08-05
参考：`vaultwarden-file-level-comparison-2026-08-05.md`（逐文件精读基线）、`vaultwarden-endpoint-audit-2026-08-05.md`（端点/鉴权/状态码核对）

---

## 1. 关键前提：重写 vs 兼容层

- 用户原始预期：尽量不改 Vaultwarden 代码，通过兼容层适配到 Workers。
- 现实判定：**该预期在当前平台不可行**（详见第 2 节阻断清单）。Vaultwarden 与 Cloudflare Workers 在运行时、框架、数据库、文件系统、线程、CPU 限额上存在根本性不兼容，"不改代码 + 薄兼容层"的工程成本远高于协议级重写。
- 因此本仓库采用**协议级兼容重写**：客户端（Web/移动/桌面/浏览器扩展）看到的端点、响应体、状态码、鉴权语义与 Vaultwarden 一致；内部实现为 Workers 原生技术栈。
- 判定标准：**功能等价以"客户端可观察行为"为准**（端点存在性、请求/响应契约、鉴权与权限语义、数据语义），不以源代码文本相似度为准。

## 2. 为什么"不改 Vaultwarden 代码"在 Workers 上不可行

| 阻断项 | Vaultwarden 依赖 | Workers 现实 | 若走"兼容层"所需成本 |
| --- | --- | --- | --- |
| 异步运行时 | tokio（网络/定时器/任务） | wasm32 无 tokio 网络栈 | 在 Workers 上重写 tokio 等价层 |
| 路由框架 | Rocket（真实 socket/TLS、guard 体系） | 无 | 重写 Rocket 兼容运行时 |
| 数据库 | Diesel/SQLx（native 驱动、连接池、迁移） | D1（另一套 API） | 为 D1 实现 diesel/sqlx 全部 trait 面 |
| 并发模型 | 同步阻塞 + 多线程 | 全异步、无线程 | 改造全库为异步 |
| 文件系统 | std::fs 本地存储附件/Send | 无，仅 R2 | 实现 fs 兼容层映射 R2 |
| 邮件 | lettre（SMTP socket） | 无 SMTP | 实现 SMTP 兼容层 |
| 外部 HTTP | reqwest（native 连接池） | fetch（标准） | 中等（reqwest 有 wasm 分支，但 VW 代码未按此编写） |
| 原生密码学 | ring/openssl/argon2 | 需 wasm 移植 | ring 有 wasm 支持，openssl/argon2 无 |
| CPU 限额 | 同步 PBKDF2 600k 迭代 | free 计划 10ms CPU/请求 | 必须卸载到 Durable Object（架构改造，非"兼容层"） |
| 后台任务 | job_scheduler_ng 线程调度 | 仅 Cron 调度器 | 改造为 Cron/DO |

**结论**：Vaultwarden 代码与上述基础设施强耦合（模型结构体带 diesel 宏、handler 用 Rocket guard、主流程用 tokio 阻塞调用），无法在"不改代码"的前提下剥离出可运行于 Workers 的模块。协议级重写是本平台唯一现实路径。

## 3. 文件清单总览

- Vaultwarden src 下 **60 个 .rs 文件**。
- 判定分布：
  - 🟢 **等价实现（有等价物，行为对齐）**：约 45 个（同名语义重写 + 平台替换）
  - 🟠 **功能替换（行为不等价，属设计决策）**：4 类（mail/storage/ratelimit/http 等，见第 5 节）
  - 🔴 **真实缺失（无等价物）**：5 个文件、4 类功能（见第 4 节）
  - 🔵 **特有扩展（VW 没有，本项目新增）**：约 30 个文件（见第 6 节）

## 4. 真实缺失（🔴 必须知晓，非"兼容性差异"）

| Vaultwarden 文件/功能 | 现状 | 影响 |
| --- | --- | --- |
| `api/admin.rs` + `src/static/admin/**` | **未实现** | `/admin` 管理界面与 API（用户管理、诊断、邀请、禁用、remove-2fa、组织管理）不可用 |
| `sso.rs`、`sso_client.rs`、`db/models/sso_auth.rs`、`api/identity.rs` 的 SSO 分支 | **未实现**，仅占位（`get_org_domain_sso_verified`、`SSO_PLACEHOLDER_ORG_ID`、config `sso:""`） | SSO/SCIM 登录不可用；`/identity/sso/*`、`/identity/connect/oidc-signin`、`/authorize` 返回 404 |
| `db/query_logger.rs` | **无等价** | 无 SQL 语句级观测（不影响功能，仅影响运维可观测性） |
| 邮件实际投递（`mail.rs` → notify 通道） | **功能替换**：Webhook/Telegram/企业微信 | **不会收到真实 SMTP 邮件**；注册验证、删除恢复、紧急访问邀请、2FA 邮件均以通知通道投递（见第 5 节） |

> 说明：这 4 类缺失在早期报告中有记录，但未单独加粗突出，造成"被当作兼容性差异处理"的观感。现单独列出，属**有意未实现**（admin/SSO 明确不宣称支持；邮件为通道替换），不是疏漏。若上述能力是硬需求，需要另行开发。

## 5. 功能替换（🟠 设计决策，行为不等价）

| Vaultwarden 文件 | warden-worker 等价物 | 行为差异 |
| --- | --- | --- |
| `mail.rs`（SMTP） | `extensions/notify/**` | 投递通道：SMTP 邮件 → Webhook/Telegram/企业微信 |
| `storage.rs`（本地磁盘） | `worker_runtime/r2_file.rs` | 附件/Send 文件：本地 → R2（上限 95 MiB、8 MiB 分片） |
| `ratelimit.rs`（governor 进程内） | Cloudflare Rate Limiting 绑定 | 限流：进程内 → 边缘命名空间（LOGIN/SEND_ACCESS/UNAUTHENTICATED） |
| `http_client.rs`（reqwest） | `worker::Fetch` | 外部 HTTP 客户端，无 SSRF 基础设施（icons 域名白名单已补） |
| `config.rs` | `meta/config.rs` + wrangler.jsonc vars + D1 密钥表 | 配置来源：环境/文件 → CF vars+Secrets |
| `main.rs` | `lib.rs` + `entry.js` + `heavy_do_routing.mjs` | 入口：进程 → Worker fetch/scheduled + HeavyDo 卸载 |
| `util.rs` | 分散（meta/format_date、auth/client_ip 等） | 等价 |
| `auth/send.rs` | `api/core/sends.rs::issue_send_access_token` | 等价 |

## 6. 特有扩展（🔵 保护项，VW 没有）

- **Passkey/密钥登录**：`/api/webauthn/*`、`/identity/accounts/webauthn/assertion-options`、PRF 状态机、`worker_runtime/webauthn.rs`
- **Turnstile 人机验证**：`/send-verify` + `/api/send-verify`
- **Webhook/Telegram/企业微信通知**：`extensions/notify/**`（10 文件）
- **Durable Object**：`NotificationsHub`（SignalR 广播）、`HeavyDo`（PBKDF2/2FA/sync CPU 卸载）
- **平台设施**：`worker_runtime/**`（router/r2_file/jwt_manager/two_factor_key_manager/background/logging/domains）、`crypto/password.rs`
- **子模块拆分**：`accounts/devices.rs`、`ciphers/{attachments,sync,sync/models}.rs`、`imports{,/models}.rs`、`meta/*`、`extensions/usage.rs`

## 7. 45 对同名文件功能等价核对（🟡 语义重写，行为已对齐）

判定标准：端点/请求响应契约/鉴权/数据语义逐项对齐（详见 `vaultwarden-file-level-comparison-2026-08-05.md` 第三节逐文件精读）。

### 7.1 已确认修复（迁移落地，原 P1/P2）

| 文件 | 原差异 | 现状 |
| --- | --- | --- |
| api/core/ciphers.rs | purge 忽略 organization 参数 | ✅ 已修：Owner 清空组织库 + 事件（L259-294） |
| api/core/accounts.rs | SIGNUPS_VERIFY 默认 true | ✅ 已修：默认 false（L607） |
| api/core/accounts.rs | 删除恢复不发邮件 | ✅ 已修：DeleteAccount action link + outbox |
| api/core/accounts.rs | rotate keys 拒绝 emergency/recovery | ✅ 已修：同步更新 key 与 reset_password_key |
| auth.rs / identity.rs | Claims 缺 iss/sstamp/devicetype/client_id/scope；refresh 无设备绑定 | ✅ 已修：Claims 补齐；devices.refresh_token 写入 + 校验 |
| error.rs + 各端点 | 状态码全局不一致 | ✅ 已修：NotFound→400、ResourceNotFound→404、密码错误 400 |
| events.rs | get_cipher_events 无权限 404/403 | ✅ 已修：空列表 |
| events.rs / organizations.rs / ciphers.rs | 事件审计缺失 | ✅ 已修：log_event/log_user_event 22+ 点 |
| organizations.rs | require_collection_manager 额外要求 access_all | ✅ 已修：对齐 ManagerHeadersLoose |
| two_factor/mod.rs + authenticator.rs | validate 硬编码 delete_if_valid | ✅ 已修：validate_get/validate_with_delete |
| two_factor/mod.rs | 缺 enforce_2fa_policy | ✅ 已修：删除最后 2FA 后吊销策略成员 |
| api/icons.rs | 无域名校验 | ✅ 已修：valid_icon_domain + 400 + immutable |
| api/notifications.rs | 缺 SyncOrgKeys=6 | ✅ 已修 |
| meta/config.rs | sso null / 时间格式 | ✅ 已修：sso:""、%Y-%m-%dT%H:%M:%S%.6fZ |
| api/core/mod.rs | 缺 404 JSON catcher | ✅ 已修：router fallback |
| db/models/organization.rs | useResetPassword 硬编码 true | ✅ 已修：按 mail_enabled 输出 |
| api/push.rs | push_auth_event deviceId null | ✅ 已修：回填 acting device |
| lib.rs 调度 | cron 子集 | ✅ 已修：purge_trashed_ciphers、cleanup_old_events |
| wrangler.jsonc / CI | migrations_dir 残留、迁移步骤 | ✅ 已修 |

### 7.2 确认等价（重写但契约一致）

| 文件 | 说明 |
| --- | --- |
| api/core/public.rs、sends.rs | 路由/响应/校验逐项等价；Send 含 Turnstile（扩展） |
| api/core/emergency_access.rs | 18 端点状态机一一对应 |
| api/core/folders.rs | 路由与响应等价（404→400 已随错误映射统一） |
| api/core/two_factor/{authenticator,duo,duo_oidc,email,yubikey,webauthn,protected_actions}.rs | 协议/响应/加固等价；delete_if_valid 已修 |
| api/identity.rs、api/notifications.rs、api/push.rs、api/web.rs | 契约等价 + 特有扩展 |
| db/models/*（19 个） | 序列化字段/枚举值/常量逐项对齐（emergency_access.rs 逐字节一致）；D1 适配 |
| crypto.rs、auth.rs、error.rs | 密码学等价、Claims 契约已修、错误体等价 |

### 7.3 仍保留的有意差异（P3，声明）

- `stamp_exception`（改密后 2 分钟豁免）未实现（OTP 已覆盖主要受保护操作）
- `Key` 恒返回 / `MasterPasswordPolicy` 空对象（可随组织策略合并精修）
- webauthn challenge 无 status/errorMessage 顶层包装（自研 passkey 协议）
- email 2FA `enabled` 布尔 vs 字符串
- 批量上限更严（move/share ≤40、bulk-collections ≤80）
- emergency_access reminder cron 缺失（仅自动 approve）
- crypto.rs 附件 ID uuid 格式（客户端视为不透明字符串）
- user.enabled、auth_requests.organization_uuid、events.policy_uuid 缺失（关联 admin/SSO 未实现）

## 8. 结论与风险

1. **文本巨大差异 ≠ 功能缺失**：技术栈（Rocket→Axum、Diesel/SQLx→D1、ring→wasm、本地→R2/DO）全换，同一功能文本必然完全不同。Beyond Compare 不适合验证本项目的功能等价性。
2. **真实缺失共 4 类**：Admin 面板、SSO/SCIM、SQL 查询日志、SMTP 邮件投递（后者为通道替换）。均为有意未实现/替换，非疏漏。
3. **功能实现不一致**集中在"功能替换"（邮件/存储/限流/HTTP/配置/入口）与 P3 级细节，客户端可观察的协议层（端点、响应、鉴权、权限、状态码）已逐项对齐并经端点审计确认。
4. **风险提示**：若业务硬依赖 SMTP 邮件或 Admin 面板，当前实现不满足；SSO 客户单不可用。其余核心密码库/组织/2FA/Send/Emergency Access 能力可用。
5. **验证边界**：本报告为静态核对（源码级）；未做远程 D1/R2/DO 部署下的全客户端端到端录制。如需更强证据，可补充协议级契约测试或实际部署验证。

## 9. 判定矩阵汇总

| 类别 | 数量 | 结论 |
| --- | ---: | --- |
| 同名等价（重写） | ~45 | 行为对齐 ✅ |
| 平台替换等价 | 8 类 | 行为等价 ✅ |
| 功能替换（邮件/存储/限流/HTTP） | 4 类 | 行为不等价，设计决策 🟠 |
| 真实缺失（admin/SSO/query_logger） | 5 文件 | 有意未实现 🔴 |
| 特有扩展 | ~30 文件 | 保护项 🔵 |
