# Warden Worker 与 Vaultwarden 端点实现审计

> 历史基线说明：本报告记录组织功能迁移开始前的仓库状态。组织功能已在同一工作树中开始实现，当前进度与剩余差异请以 `organization-migration-status-2026-08-04.md` 为准；下文“组织端点未实现”等结论不代表当前工作树。

审计日期：2026-08-04

## 1. 审计基线与结论

- Warden Worker：`d89466593dd4c799cb9a311ff65211fb7f927dc8`
- Vaultwarden：`2629bcbe1380c894e3a7f52cafcac3988edb8fbb`
- Warden Worker 路由入口：[src/worker_runtime/router.rs](../src/worker_runtime/router.rs)
- Vaultwarden core 路由入口：[src/api/core/mod.rs](../../vaultwarden/src/api/core/mod.rs)
- Vaultwarden 组织实现：[src/api/core/organizations.rs](../../vaultwarden/src/api/core/organizations.rs)

最终结论：**本项目没有与 Vaultwarden 保持完整一致。**

个人密码库的主要成功路径已经大体兼容，尤其是 accounts、folders、personal ciphers、Sends、TOTP/Email/WebAuthn 2FA；但这不等于实现一致。当前仍存在全局错误状态码、JWT、配置与版本响应、Push、事件、图标、文件限制等可观察差异。

组织功能目前不是“尚未接通 UI”，而是从数据库、权限、同步到端点整条能力链均未实现：Vaultwarden `organizations.rs` 的 77 个方法-路径组合中，Worker 只注册了同名的 `GET /api/collections`，而且它仅返回空数组；其余 76 个均未注册。组织依赖的另外 25 个 cipher 管理/共享端点、3 个事件查询端点、1 个 Public API 导入端点及组织 API Key 登录也没有实现。

### 路由量化结果

| 指标 | 数量 | 说明 |
| --- | ---: | --- |
| Worker 路径模板 | 135 | `src/worker_runtime/router.rs` 中的 `.route(...)` |
| Worker 方法-路径注册 | 175 | 包含 `/api`、`/identity`、Web、上传和扩展端点 |
| Worker `/api` 注册 | 149 | 包含尾斜杠别名等重复注册 |
| Worker `/api` 规范化唯一注册 | 142 | 参数名和尾斜杠归一化后 |
| Vaultwarden `/api` 方法-路径 | 251 | 不含单独挂载的 `POST /events/collect` |
| 双方同方法、同规范化 `/api` 路径 | 122 | 仅代表路由存在，不代表行为一致 |
| Worker 缺失的 Vaultwarden `/api` 路径 | 129 | 76 organization + 25 cipher + 18 emergency + 6 Duo/YubiKey + 3 events + 1 public |
| Worker 独有 `/api` 唯一路径/方法 | 20 | Passkey、兼容别名、D1 usage、空壳端点、HEAD 等 |

## 2. 判定规则

- **个人兼容**：个人密码库的请求/成功响应和主要副作用与当前 Vaultwarden 基本相符；仍受第 3 节全局差异影响。
- **部分一致**：路径存在，但鉴权、数据范围、响应、状态码或副作用有明确差异。
- **空壳**：只为避免客户端 404 而返回空值，没有对应业务实现。
- **Worker 扩展**：Vaultwarden 基线没有这个方法-路径组合，是本项目自定义能力或兼容别名。
- **缺失**：Vaultwarden 有实现，而 Worker 没有注册对应端点。

本报告中的“个人兼容”不表示逐字节等价，也不表示组织场景可用。

## 3. 跨端点的实现差异

### 3.1 数据模型不具备组织语义

Worker 的 [sql/schema.sql](../sql/schema.sql) 只有 users、folders、ciphers、archives、attachments、sends、2FA、devices/auth requests 和密钥表。不存在以下 Vaultwarden 核心实体或关系：

- organizations
- users_organizations / Membership
- collections
- ciphers_collections
- users_collections
- groups、groups_users、collections_groups
- org_policies
- organization_api_key
- events
- invitations
- favorites 和 folders_ciphers 的逐用户关联

`ciphers.organization_id` 和 `sends.organization_id` 虽然存在，但没有组织外键和权限关系，不能据此实现组织能力。

此外，`users_single_user_before_insert` 触发器会拒绝第二个用户。组织成员邀请、接受、确认、撤销和恢复因此在数据库层就无法成立。

### 3.2 组织权限守卫完全缺失

Vaultwarden 组织操作不是统一的“已登录即可”，而是根据 Membership 状态和角色、collection 直接授权、group 授权、`accessAll`、`readOnly`、`hidePasswords`、`manage`、Custom Role 权限分别判断。Worker 目前只有用户 JWT 和 security stamp 校验，没有对应的 Owner/Admin/Manager/可访问集合守卫。

如果只移植路由而不先移植权限模型，会直接引入跨用户读取或写入风险。

### 3.3 sync/profile 是明确的个人库裁剪

[src/api/core/ciphers/sync.rs](../src/api/core/ciphers/sync.rs) 固定返回：

- `profile.organizations = []`
- `profile.providers = []`
- `profile.providerOrganizations = []`
- `profile.premiumFromOrganization = false`
- 顶层 `collections = []`
- 顶层 `policies = []`

Cipher、Folder 和 Send 查询都限定为当前 `user_id`。组织 cipher 通过成员、集合和组授权进入同步结果的逻辑不存在。

[src/api/core/accounts.rs](../src/api/core/accounts.rs) 的 profile 同样固定返回空组织数据。

### 3.4 Cipher 被显式限制为个人库

[src/db/models/cipher.rs](../src/db/models/cipher.rs) 的 `validate_for_personal_vault` 在 `organizationId` 非空时直接失败；创建 cipher 时 collectionIds 非空也会失败。

Worker 将 `favorite`、`folder_id` 直接存到 cipher 上。Vaultwarden 对共享组织 cipher 使用用户维度的 favorites 和 folders_ciphers；否则同一个共享 cipher 无法为不同成员保存不同收藏和文件夹状态。

附件元数据也直接绑定 `user_id`，没有组织可访问/可管理校验。

### 3.5 组织策略没有进入业务判断

Worker 没有 OrgPolicy 数据和读取逻辑，因此不会执行 Vaultwarden 中会跨端点生效的策略，包括但不限于：

- Single Organization
- Two-factor Authentication
- Master Password
- Disable Send
- Send Options / Disable Hide Email
- Account Recovery Administration
- Remove individual vault
- Organization Data Ownership

这会影响登录、组织创建/加入、密码校验、Send 创建/更新、账户恢复和 cipher 归属，不只是 `/organizations/*`。

### 3.6 全局错误状态码不一致

Worker 的 [src/error.rs](../src/error.rs) 将 `NotFound` 固定映射为 404、`Unauthorized` 固定映射为 401。Vaultwarden 的多数 `err!` 业务错误默认是 400，只有显式错误码或请求守卫失败时才使用其他状态码。

因此大量“密码错误、资源不存在、资源不属于当前用户”的失败响应虽然 JSON 错误体字段大体相同，HTTP 状态码并不一致。受影响端点横跨 accounts、ciphers、folders、attachments、Sends、devices 和 2FA。

### 3.7 JWT 与 refresh token 实现不一致

Worker 的 [src/auth.rs](../src/auth.rs) Claims 缺少 Vaultwarden access token 中的 `iss`、`sstamp`、`devicetype`、`client_id`、`scope` 等字段，字段名也使用 `security_stamp` 而非 `sstamp`。Worker 使用 D1 中的 HMAC secret；Vaultwarden 使用自己的 JWT issuer/key 基础设施。

Worker refresh token 复用本地 Claims/独立 HMAC secret；Vaultwarden 使用独立 RefreshJwtClaims、AuthMethod、device token 并参与设备记录校验和轮换。因此个人客户端的外层 token 响应可以工作，但内部 token 契约并不等价。

`client_credentials` 只支持 `scope=api` 与 `user.<id>`；Vaultwarden 还支持 `scope=api.organization`、`organization.<id>` 和 OrganizationApiKey。

### 3.8 通知、事件和后台任务只覆盖个人库子集

Worker 的 Durable Object 能广播个人 cipher/folder/send/user/auth-request 更新，但 cipher 通知始终写 `OrganizationId = null`、`CollectionIds = null`，也没有向组织成员集合广播的目标解析。

`POST /events/collect` 只解析并丢弃事件；Vaultwarden 在启用事件记录时会验证并持久化组织、用户和 cipher 事件，供组织事件端点读取。

Worker Cron 只清理过期 Send。Vaultwarden 还包含 trash cipher、auth request、event、emergency access、incomplete 2FA、incomplete SSO 等定时任务。

## 4. Worker 现有端点逐项核对

下表覆盖 `src/worker_runtime/router.rs` 的全部路由。共享同一 handler 的方法或兼容别名合并在一行。

### 4.1 Web、静态与公共入口

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET /demo.html` | Worker 扩展 | 本地演示页，Vaultwarden 无此端点 |
| `GET /.well-known/apple-app-site-association` | 个人兼容 | 返回 Bitwarden app association，静态结果基本相符 |
| `GET /css/vaultwarden.css` | 部分一致 | 都提供 Vaultwarden CSS，但 Worker 的动态规则和配置来源为本项目实现 |
| `GET /icons/{*path}` | 部分一致 | Worker 直接代理 `vault.bitwarden.com` 并固定缓存；Vaultwarden 有域名/IP 安全校验、本地/外部图标服务、正负缓存和 fallback |
| `GET /send-verify`、`POST /api/send-verify` | Worker 扩展 | Turnstile 匿名 Send 验证流程 |

### 4.2 Identity、注册和账户

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `POST /identity/accounts/prelogin` | 个人兼容 | 当前 KDF settings、salt 响应已跟进上游 |
| `POST /identity/accounts/prelogin/password` | 个人兼容 | Vaultwarden 有同一路径 |
| `POST /api/accounts/prelogin` | 个人兼容 | Vaultwarden core 对应端点 |
| `POST /api/accounts/prelogin/password` | Worker 扩展 | `/api` 下的 password 别名不在基线中 |
| `POST /identity/accounts/register`、`POST /identity/accounts/register/finish` | 部分一致 | Worker 受 ALLOWED_EMAILS 和单用户限制；不具备邀请/组织加入语义 |
| `POST /identity/accounts/register/send-verification-email` | 部分一致 | 无 SMTP 时令牌返回可兼容，但 Worker 通知通道和单用户注册约束不同 |
| `POST /identity/accounts/register/verification-email-clicked` | 部分一致 | 注册验证流程为 Worker 本地实现 |
| `POST /identity/connect/token` | 部分一致 | 个人 password/refresh/user API key 流程大体可用；JWT、refresh、SSO、组织 API key、Push device token 均不一致 |
| `GET/POST/PUT /api/accounts/profile` | 部分一致 | 个人字段基本相符；组织、provider、organization premium 固定为空/false |
| `PUT /api/accounts/avatar` | 个人兼容 | 个人头像颜色更新基本相符 |
| `POST /api/accounts/avatar` | Worker 扩展 | 方法别名 |
| `POST /api/accounts/security-stamp` | 个人兼容 | 个人成功路径相符，错误状态码存在全局差异 |
| `GET /api/accounts/revision-date` | 个人兼容 | 返回个人 vault revision |
| `POST /api/accounts/password-hint` | 部分一致 | Worker 使用本项目通知/webhook 能力，不等价于 Vaultwarden SMTP 分支 |
| `POST /api/accounts/request-otp`、`POST /api/accounts/verify-otp` | 个人兼容 | protected action 主路径存在 |
| `POST /accounts/request-otp`、`POST /accounts/verify-otp` | Worker 扩展 | 无 `/api` 前缀的兼容别名 |
| `POST /api/accounts/verify-password` | 部分一致 | 无组织策略时返回空 masterPasswordPolicy；失败状态码可能为 401 而非 400 |
| `POST /accounts/verify-password` | Worker 扩展 | 无 `/api` 前缀的兼容别名 |
| `POST /api/accounts/password` | 个人兼容 | 个人密码/密钥更新路径基本相符；无组织/紧急访问关联更新 |
| `POST /api/accounts/email` | 个人兼容 | 个人邮箱更新主流程基本相符；注册与通知配置不同 |
| `POST /api/accounts/kdf` | 个人兼容 | 个人 KDF 更新及 cipher 重加密主路径基本相符 |
| `POST /api/accounts/key-management/rotate-user-account-keys` | 部分一致 | 明确拒绝 organization account recovery 和 emergency access unlock data |
| `GET /api/tasks` | 个人兼容 | 与 Vaultwarden 当前任务响应对应 |
| `GET /api/accounts/tasks` | Worker 扩展 | 方法-路径别名 |
| `POST /api/accounts/delete`、`DELETE /api/accounts` | 个人兼容 | 个人资源删除可用；不存在组织所有权转移、membership/event 清理 |
| `POST /api/accounts/delete-recover`、`POST /api/accounts/delete-recover-token` | 部分一致 | 个人删除恢复流程存在；邮件/部署配置不同 |
| `POST /api/accounts/keys` | 个人兼容 | 个人非对称密钥更新基本相符 |
| `GET /api/users/{user_id}/public-key` | 个人兼容 | 单用户范围可用；不能支撑真实组织成员批量密钥场景 |
| `POST /api/accounts/api-key`、`POST /api/accounts/rotate-api-key` | 部分一致 | user API key 可用；token claims 和组织 API key 能力缺失 |
| `POST /api/accounts/verify-email`、`POST /api/accounts/verify-email-token`、`POST /api/accounts/email-token` | 部分一致 | 主响应大体兼容；邮件/通知和状态码分支不同 |
| `POST /api/accounts/set-password` | 部分一致 | 不处理组织邀请 identifier、emergency access 邀请和相关欢迎流程 |

### 4.3 Devices 与 Auth Requests

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET /api/devices` | 个人兼容 | 个人设备与待处理 auth request 信息基本相符 |
| `GET /api/devices/identifier/{id}` | 个人兼容 | 个人设备查询基本相符 |
| `GET /api/devices/knowndevice` | 个人兼容 | 请求头和布尔响应基本相符 |
| `POST/PUT /api/devices/identifier/{id}/token` | 部分一致 | Worker 忽略提交的 pushToken，只更新设备元数据；Vaultwarden 可注册 Push |
| `POST/PUT /api/devices/identifier/{id}/clear-token` | 部分一致 | Worker 要求 JWT/security stamp 且实际 no-op；Vaultwarden 清理 Push token，鉴权路径不同 |
| `GET/POST /api/auth-requests` | 个人兼容 | 主 Auth Request 流程可用 |
| `GET /api/auth-requests/pending` | 个人兼容 | 主路径可用 |
| `GET/PUT /api/auth-requests/{id}` | 个人兼容 | 查询/批准主路径可用 |
| `GET /api/auth-requests/{id}/response` | 个人兼容 | code 验证和响应主路径可用 |
| 上述 `/api/auth-requests/.../` 尾斜杠路径 | Worker 扩展 | 兼容别名，规范化后与主路径相同 |
| `POST /api/auth-requests/admin-request[/]` | Worker 扩展 | 指向普通创建 handler，Vaultwarden 基线无此单独路径 |

### 4.4 Two-factor Authentication

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET /api/two-factor` | 部分一致 | 只覆盖 Authenticator、Email、WebAuthn；不含 Duo/YubiKey，也无组织 2FA policy |
| `GET /api/two-factor/get-device-verification-settings` | 个人兼容 | 当前个人响应基本相符 |
| `POST /api/two-factor/get-authenticator` | 个人兼容 | TOTP 查询/初始化主流程存在 |
| `POST/PUT/DELETE /api/two-factor/authenticator` | 个人兼容 | Vaultwarden 三种方法均存在；Worker 另有本地回放防护实现 |
| `POST /api/two-factor/authenticator/request` | Worker 扩展 | 新客户端/兼容流程别名 |
| `POST /api/two-factor/authenticator/enable` | Worker 扩展 | 新客户端/兼容流程别名 |
| `POST /api/two-factor/authenticator/disable` | Worker 扩展 | 新客户端/兼容流程别名 |
| `POST /api/two-factor/get-email`、`POST /api/two-factor/send-email`、`PUT /api/two-factor/email` | 部分一致 | Email 2FA 主协议存在，但发送依赖 Worker webhook/通知配置 |
| `DELETE /api/two-factor/email` | Worker 扩展 | Vaultwarden 基线通过通用 disable，不注册此方法 |
| `POST /two-factor/send-email-login`、`POST /api/two-factor/send-email-login` | 部分一致 | `/api` 路径与上游对应；无前缀路径是别名；发送通道不同 |
| `POST /api/two-factor/get-webauthn`、`POST /api/two-factor/get-webauthn-challenge` | 个人兼容 | WebAuthn 2FA 查询/挑战主路径存在 |
| `POST/PUT/DELETE /api/two-factor/webauthn` | 个人兼容 | WebAuthn 2FA 注册、更新、删除主路径存在 |
| `POST/PUT /api/two-factor/disable`、`POST /api/two-factor/get-recover` | 个人兼容 | Vaultwarden 对应方法存在 |
| `POST /api/two-factor/recover` | Worker 扩展 | 当前 Vaultwarden 基线无此方法-路径 |

Vaultwarden 缺失于 Worker 的 2FA 端点详见第 5 节：Duo 3 个、YubiKey 3 个。

### 4.5 Sends

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET/POST /api/sends` | 部分一致 | 个人 Send CRUD/序列化基本兼容；没有 DisableSend/DisableHideEmail 等组织策略 |
| `GET/PUT/DELETE /api/sends/{send_id}` | 部分一致 | 个人主路径兼容；错误状态码和策略不同 |
| `PUT /api/sends/{send_id}/remove-password` | 个人兼容 | 个人主路径基本相符 |
| `POST /api/sends/file` | 部分一致 | legacy 上传协议存在；R2、95 MiB 固定上限与 Vaultwarden 存储/配额配置不同 |
| `POST /api/sends/file/v2` | 部分一致 | v2 元数据流程存在；Worker 返回体/上传目标和存储实现不同 |
| `POST /api/sends/{send_id}/file/{file_id}` | 部分一致 | multipart 数据写入 R2；上游由本地/配置存储实现 |
| `POST /sends/{send_id}/file/{file_id}` | Worker 扩展 | 无 `/api` 前缀的直传兼容路径 |
| `POST /api/sends/access`、`POST /api/sends/access/{access_id}` | 部分一致 | 最大访问次数与生命周期处理已跟进上游；Worker 额外加入 Turnstile cookie/pass |
| `POST /api/sends/access/file/{file_id}`、`POST /api/sends/{send_id}/access/file/{file_id}` | 部分一致 | 匿名文件授权主流程存在；增加 Turnstile/R2 语义 |
| `GET /api/sends/{send_id}/{file_id}` | 部分一致 | 可下载，但 URL、R2 streaming 和固定长度响应为 Worker 实现 |

14 个 Vaultwarden Send 方法-路径均已注册，但不能据此判定实现完全一致。

### 4.6 Compatibility、Sync 与组织占位

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET /api/collections` | 空壳 | Vaultwarden 返回当前用户可访问 collection；Worker 验证 security stamp 后固定返回 `[]` |
| `GET /api/policies` | 空壳 / Worker 扩展 | Vaultwarden 没有对应的全局独立路径；真实 policy 来自 sync/profile 和 `/organizations/{id}/policies*` |
| `GET /api/organizations` | 空壳 / Worker 扩展 | Vaultwarden 没有对应的全局独立路径；真实组织数据来自 profile/sync 和 scoped routes |
| `GET /api/sync` | 部分一致（严重） | 个人 Folder/Cipher/Send 可同步；组织、collection、policy、provider 和共享 cipher 可见性全部缺失 |

### 4.7 Ciphers 与 Attachments

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET/POST/DELETE /api/ciphers` | 部分一致 | 个人列表/创建别名/批量硬删存在；只查询 user-owned cipher，组织访问模型缺失 |
| `POST /api/ciphers/create` | 部分一致 | 个人创建主路径可用；拒绝 organizationId 和 collectionIds |
| `GET/POST/PUT/DELETE /api/ciphers/{id}` | 部分一致 | 个人 CRUD 基本兼容；不存在 admin/share/collection 权限分支 |
| `GET /api/ciphers/{id}/details` | 部分一致 | 个人 cipherDetails 序列化已跟进；组织 collection/access 信息缺失 |
| `POST/PUT /api/ciphers/{id}/partial` | 部分一致 | 个人 favorite/folder 更新可用；存储模型不能表达共享 cipher 的逐用户状态 |
| `PUT /api/ciphers/{id}/delete`、`POST /api/ciphers/{id}/delete` | 部分一致 | 个人软删/硬删主路径存在；无 organization admin 变体 |
| `PUT /api/ciphers/{id}/restore` | 部分一致 | 个人恢复可用；无 restore-admin |
| `PUT /api/ciphers/{id}/archive`、`PUT /api/ciphers/{id}/unarchive` | 个人兼容 | archive 为用户维度，个人场景基本相符 |
| `PUT/POST /api/ciphers/delete` | 部分一致 | 个人批量软/硬删可用；无 delete-admin |
| `PUT /api/ciphers/restore`、`PUT /api/ciphers/archive`、`PUT /api/ciphers/unarchive` | 个人兼容 | 个人批量操作主路径存在 |
| `POST /api/ciphers/purge` | 部分一致（严重） | 只清理个人库；同一路径的 organization query/admin purge 语义不存在 |
| `POST /api/ciphers/import` | 个人兼容 | 个人导入主路径存在；组织导入另有端点且缺失 |
| `POST/PUT /api/ciphers/move` | 个人兼容 | 个人 folder move 主路径存在 |
| `POST /api/ciphers/{cipher_id}/attachment/v2` | 部分一致 | 个人附件元数据创建可用；无组织访问/admin 语义 |
| `POST /api/ciphers/{cipher_id}/attachment` | 部分一致 | legacy 上传可用；R2/固定大小限制不同 |
| `GET/POST/DELETE /api/ciphers/{cipher_id}/attachment/{attachment_id}` | 部分一致 | 个人元数据/上传/删除可用；无 share/admin 变体，v2 上传成功体也不完全相同 |
| `POST /api/ciphers/{cipher_id}/attachment/{attachment_id}/delete` | 个人兼容 | 个人兼容删除路径 |
| `POST /ciphers/{cipher_id}/attachment/{attachment_id}` | Worker 扩展 | 无 `/api` 前缀的直传路径 |
| `GET /attachments/{cipher_id}/{attachment_id}` | 部分一致 | 下载可用；token、R2 和 streaming 为 Worker 实现 |

### 4.8 Folders、Domains、Meta 与 Events

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET/POST /api/folders` | 个人兼容 | 个人列表/创建主路径基本相符 |
| `GET/POST/PUT/DELETE /api/folders/{id}` | 个人兼容 | 个人 CRUD 主路径基本相符；失败状态码受全局差异影响 |
| `POST /api/folders/{id}/delete` | 个人兼容 | 兼容删除路径存在 |
| `GET/POST/PUT /api/settings/domains` | 个人兼容 | equivalent domains/excluded globals 主路径基本相符 |
| `GET /api/config` | 部分一致 | `environment.sso` 为 null 而上游为 `""`；域名和注册禁用来源不同；只暴露固定 featureStates 子集 |
| `GET/HEAD /alive`、`GET/HEAD /api/alive` | 部分一致 | GET 会检查 D1；Worker 增加 HEAD；时间格式不是固定微秒 `Z` |
| `GET /api/now` | 部分一致 | Worker 使用默认 RFC3339，Vaultwarden 固定微秒和 `Z` |
| `GET /api/version` | 不一致 | Worker 返回 Cargo `1.3.0`，Vaultwarden 返回构建 VERSION（本基线仓库为 `1.37.1` 描述） |
| `GET /api/hibp/breach` | 个人兼容 | HIBP/无 API key 分支基本复刻；错误封装和 HTTP client 不同 |
| `POST /events/collect` | 部分一致 | 只要求可解 JWT 并丢弃事件；未校验 security stamp、未持久化、不能供组织审计查询 |

### 4.9 Passkey/WebAuthn 与运维扩展

| Worker 方法与路径 | 判定 | 主要差异 |
| --- | --- | --- |
| `GET /api/webauthn` | 不一致 | Vaultwarden 明确返回空 list，因为尚不支持 passkey login；Worker 返回实际凭据 |
| `POST /api/webauthn` | Worker 扩展 | 创建 passkey credential |
| `POST /api/webauthn/attestation-options` | Worker 扩展 | passkey 注册挑战 |
| `POST /api/webauthn/prf-probe` | Worker 扩展 | PRF 探测 |
| `POST /api/webauthn/assertion-options` | Worker 扩展 | passkey 断言挑战 |
| `PUT /api/webauthn/{credential_id}` | Worker 扩展 | 更新凭据 |
| `POST /api/webauthn/{credential_id}/delete` | Worker 扩展 | 删除凭据 |
| `GET/POST /accounts/webauthn/assertion-options` | Worker 扩展 | 无 `/identity` 前缀的 passkey login 入口 |
| `GET/POST /identity/accounts/webauthn/assertion-options` | Worker 扩展 | Vaultwarden 当前基线无 passkey login 实现 |
| `GET /api/d1/usage` | Worker 扩展 | Cloudflare D1 用量端点 |

## 5. Vaultwarden 已实现但 Worker 缺失的端点

### 5.1 Organizations：76 个未注册，1 个空壳

以下按能力分组列出 Vaultwarden `organizations.rs` 的全部路由。唯一同路径的是 `GET /api/collections`，但 Worker 仅返回空数组，因此也不能算实现一致。

#### 组织生命周期

- `POST /api/organizations`
- `GET|POST|PUT|DELETE /api/organizations/{org_id}`
- `POST /api/organizations/{org_id}/delete`
- `POST /api/organizations/{org_id}/leave`
- `GET /api/organizations/{identifier}/auto-enroll-status`
- `POST /api/organizations/domain/sso/verified`

#### Collections

- `GET /api/collections`：Worker 空壳
- `GET /api/organizations/{org_id}/collections`
- `GET /api/organizations/{org_id}/collections/details`
- `POST /api/organizations/{org_id}/collections`
- `POST /api/organizations/{org_id}/collections/bulk-access`
- `POST|PUT|DELETE /api/organizations/{org_id}/collections/{col_id}`
- `POST /api/organizations/{org_id}/collections/{col_id}/delete`
- `DELETE /api/organizations/{org_id}/collections`（bulk）
- `GET /api/organizations/{org_id}/collections/{col_id}/details`
- `GET /api/organizations/{org_id}/collections/{col_id}/users`

#### 组织 Cipher 与导入

- `GET /api/ciphers/organization-details`
- `POST /api/ciphers/import-organization`
- `POST /api/ciphers/bulk-collections`

#### 成员邀请与管理

- `GET /api/organizations/{org_id}/users`
- `POST /api/organizations/{org_id}/users/invite`
- `POST /api/organizations/{org_id}/users/reinvite`
- `POST /api/organizations/{org_id}/users/{member_id}/reinvite`
- `POST /api/organizations/{org_id}/users/{member_id}/accept`
- `POST /api/organizations/{org_id}/users/confirm`
- `POST /api/organizations/{org_id}/users/{member_id}/confirm`
- `GET /api/organizations/{org_id}/users/mini-details`
- `GET|POST|PUT|DELETE /api/organizations/{org_id}/users/{member_id}`
- `DELETE /api/organizations/{org_id}/users`（bulk）
- `POST /api/organizations/{org_id}/users/public-keys`
- `PUT /api/organizations/{org_id}/users/{member_id}/revoke`
- `PUT /api/organizations/{org_id}/users/revoke`（bulk）
- `PUT /api/organizations/{org_id}/users/{member_id}/restore`
- `PUT /api/organizations/{org_id}/users/{member_id}/restore/vnext`
- `PUT /api/organizations/{org_id}/users/restore`（bulk）

#### Policies 与 billing compatibility

- `GET /api/organizations/{org_id}/policies`
- `GET /api/organizations/{org_id}/policies/token`
- `GET /api/organizations/{org_id}/policies/master-password`
- `GET /api/organizations/{org_id}/policies/{pol_type}`
- `PUT /api/organizations/{org_id}/policies/{pol_type}`
- `PUT /api/organizations/{org_id}/policies/{pol_type}/vnext`
- `GET /api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password`
- `GET /api/plans`
- `GET /api/organizations/{org_id}/billing/metadata`
- `GET /api/organizations/{org_id}/billing/vnext/warnings`
- `GET /api/organizations/{org_id}/billing/vnext/self-host/metadata`

#### Groups

- `GET /api/organizations/{org_id}/groups`
- `GET /api/organizations/{org_id}/groups/details`
- `POST /api/organizations/{org_id}/groups`
- `GET|POST|PUT|DELETE /api/organizations/{org_id}/groups/{group_id}`
- `GET /api/organizations/{org_id}/groups/{group_id}/details`
- `POST /api/organizations/{org_id}/groups/{group_id}/delete`
- `DELETE /api/organizations/{org_id}/groups`（bulk）
- `GET|PUT /api/organizations/{org_id}/groups/{group_id}/users`
- `POST /api/organizations/{org_id}/groups/{group_id}/delete-user/{member_id}`

#### Keys、Account Recovery、Export 与 API Key

- `POST /api/organizations/{org_id}/keys`
- `GET /api/organizations/{org_id}/public-key`
- `GET /api/organizations/{org_id}/keys`
- `PUT /api/organizations/{org_id}/users/{member_id}/recover-account`
- `PUT /api/organizations/{org_id}/users/{member_id}/reset-password`
- `GET /api/organizations/{org_id}/users/{member_id}/reset-password-details`
- `PUT /api/organizations/{org_id}/users/{user_id}/reset-password-enrollment`
- `GET /api/organizations/{org_id}/export`
- `POST /api/organizations/{org_id}/api-key`
- `POST /api/organizations/{org_id}/rotate-api-key`

### 5.2 组织依赖但位于 organizations.rs 外的端点

Vaultwarden `ciphers.rs` 的以下 25 个方法-路径未实现：

- `GET|POST|PUT|DELETE /api/ciphers/{cipher_id}/admin`
- `POST|DELETE /api/ciphers/admin`（创建/批量删除）
- `POST|PUT /api/ciphers/{cipher_id}/share`
- `PUT /api/ciphers/share`（bulk）
- `POST|PUT /api/ciphers/{cipher_id}/collections`
- `POST|PUT /api/ciphers/{cipher_id}/collections_v2`
- `POST|PUT /api/ciphers/{cipher_id}/collections-admin`
- `POST|PUT /api/ciphers/{cipher_id}/delete-admin`
- `POST|PUT /api/ciphers/delete-admin`（bulk）
- `PUT /api/ciphers/{cipher_id}/restore-admin`
- `PUT /api/ciphers/restore-admin`（bulk）
- `POST /api/ciphers/{cipher_id}/attachment-admin`
- `POST /api/ciphers/{cipher_id}/attachment/{attachment_id}/share`
- `POST /api/ciphers/{cipher_id}/attachment/{attachment_id}/delete-admin`
- `DELETE /api/ciphers/{cipher_id}/attachment/{attachment_id}/admin`

另缺少：

- `GET /api/organizations/{org_id}/events`
- `GET /api/ciphers/{cipher_id}/events`
- `GET /api/organizations/{org_id}/users/{member_id}/events`
- `POST /api/public/organization/import`
- `POST /identity/connect/token` 中的 `scope=api.organization` / `organization.{id}` 分支
- 组织 cipher/collection/member 的实时通知目标解析与 payload

### 5.3 Emergency Access：18 个全部缺失

- `GET /api/emergency-access/granted`
- `GET /api/emergency-access/trusted`
- `POST /api/emergency-access/invite`
- `GET|POST|PUT|DELETE /api/emergency-access/{id}`
- `POST /api/emergency-access/{id}/accept`
- `POST /api/emergency-access/{id}/approve`
- `POST /api/emergency-access/{id}/confirm`
- `POST /api/emergency-access/{id}/delete`
- `POST /api/emergency-access/{id}/initiate`
- `POST /api/emergency-access/{id}/password`
- `GET /api/emergency-access/{id}/policies`
- `POST /api/emergency-access/{id}/reinvite`
- `POST /api/emergency-access/{id}/reject`
- `POST /api/emergency-access/{id}/takeover`
- `POST /api/emergency-access/{id}/view`

### 5.4 Duo 与 YubiKey：6 个全部缺失

- `POST /api/two-factor/get-duo`
- `POST|PUT /api/two-factor/duo`
- `POST /api/two-factor/get-yubikey`
- `POST|PUT /api/two-factor/yubikey`

### 5.5 `/api` 统计之外仍缺失的 Vaultwarden 子系统

- Identity SSO：`/identity/sso/prevalidate`、OIDC signin、authorize 及 authorization_code 登录分支
- Admin Web/API：Vaultwarden `/admin/*` 管理界面与管理操作
- 真正的 Push 注册、注销和 Bitwarden Push relay
- Vaultwarden web 静态文件/fallback 的完整服务语义；Worker 改由 Workers Assets 承担
- 组织邀请邮件、确认邮件、account recovery 和 emergency access 邮件流程

## 6. 组织功能的正确实现顺序

组织支持不能按“缺哪个路由补哪个路由”推进。建议按以下依赖顺序实施并逐层加入契约测试：

1. **D1 schema 与迁移**：Organization、Membership、Collection、CipherCollection、UserCollection、Group/GroupUser/CollectionGroup、OrgPolicy、OrganizationApiKey、Event；拆分 favorite/folder 的逐用户关系；解除单用户约束。
2. **权限查询层**：确认 membership 状态、Owner/Admin/User/Manager/Custom、accessAll、collection direct/group permissions、readOnly/hidePasswords/manage。
3. **Profile 与 Sync**：先让组织、collections、policies 和共享 ciphers 以正确数据范围进入客户端，再实现管理写端点。
4. **组织生命周期和成员状态机**：create/invite/accept/confirm/edit/revoke/restore/delete/leave，包含密钥和邮件 token。
5. **Collection、Group 与共享 Cipher**：所有读写必须复用同一权限判定；附件和批量操作一起覆盖。
6. **Policies 与跨端点 enforcement**：登录、2FA、Send、密码、组织加入、账户恢复等调用点同时接入。
7. **Events、Notifications、API Key、Import/Export 与 Account Recovery**。
8. **客户端契约矩阵**：Web/Desktop/Browser/Mobile 对 create org、invite、accept、sync、share、collection/group permissions、revoke/restore、policy 的端到端测试。

## 7. 风险分级

| 级别 | 问题 | 影响 |
| --- | --- | --- |
| P0 | 组织数据模型和权限模型缺失 | 组织功能无法安全实现 |
| P0 | sync/profile/collections/policies 固定为空 | 客户端无法看到任何组织状态或共享数据 |
| P0 | 单用户触发器 | 成员邀请和多用户组织从数据库层不可成立 |
| P1 | 组织 cipher/admin/share/collection 端点缺失 | 无法管理或共享密码项 |
| P1 | policy 不执行 | 即使补组织 CRUD，也会绕过安全策略 |
| P1 | 错误状态码全局不一致 | 客户端错误分支可能与 Vaultwarden 不同 |
| P1 | JWT/refresh/org API key 不一致 | 组织 CLI/Public API 和 token 验证无法兼容 |
| P2 | Push、events、cron 子集 | 跨成员实时同步、审计和生命周期清理不完整 |
| P2 | config/version/now/icons/文件限制差异 | 可观察兼容性与运维行为不完全相同 |
| P3 | Worker 独有 Passkey、Turnstile、D1 usage、别名 | 有意扩展，应明确作为 divergence 维护 |

## 8. 审计边界

本次是基于两个指定 commit 的静态代码审计与现有测试验证，不包含：

- 实际 Cloudflare 远程 D1/R2/DO 部署验证
- 真实 Bitwarden Web/Desktop/Browser/Mobile 的完整端到端协议录制
- 上游配置所有排列组合（SMTP、Push、SSO、Duo、YubiKey、Events、Groups 等）的动态验证
- 性能、D1 事务并发、R2 大文件和跨区域一致性压测

因此报告可以确认“哪些代码路径存在及其静态语义”，不能把“个人成功路径大体兼容”提升为“与 Vaultwarden 完全一致”。
