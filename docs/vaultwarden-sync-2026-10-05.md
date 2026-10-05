# Vaultwarden 最近 10 次更新的逻辑合入记录

- 来源：`D:\gitrepo\vaultwarden` 当前 HEAD `1f99d9d276c41107eeaddd086ef840c28279cb7d`。
- 审阅范围：`cc67d644f62605cb46f4d16c4a2eed1a861cc8bb..1f99d9d276c41107eeaddd086ef840c28279cb7d`，即任务开始时 `git log -10` 的 10 次提交。
- 目标：`D:\gitrepo\warden-worker`，开始时 HEAD 为 `fbf605e340150d7929e17f433ca0b8f97d5c81c0`，工作树干净。
- 处理原则：按个人单用户 Workers/D1/R2/DO 架构移植后端行为；前端与动态 CSS 更新由用户手动处理。

## 逐提交结论

| 提交 | 上游更新 | 本仓库处理 |
| --- | --- | --- |
| `d2660324` / #7554 | 已撤销组织成员不能继续访问组织密码项 | 不适用：本仓库没有组织成员、组或集合授权模型，个人数据继续按 `user_id` 校验所有权。该提交已在上一轮同步中审阅。 |
| `32098ca7` / #7763 | 用户访问须已确认组织成员；管理员视图保持独立 | 不适用：无组织成员及管理员组织视图。已在上一轮审阅。 |
| `061694d0` / #7774 | 修复 Docker/xx-cargo 的 Cortex-A53 链接参数 | 不适用：本仓库发布 Wasm 到 Workers，不使用原生 ARM/Docker 构建。已在上一轮审阅。 |
| `44444420` / #7802 | `undetermined-cipher-scenario-logic` 功能开关 | 已合入 `/api/config.featureStates`；客户端负责实现表单提交后判断新增/更新登录项的行为。 |
| `cb89088b` / #7798 | Windows 原生凭据同步功能开关 | 已合入 `windows-native-credential-sync`。 |
| `f9f011d5` / #7759 | 禁止修改邮箱时隐藏整个修改邮箱区域 | **前端手动处理**：保留现有动态 CSS 和其配置，未移植此项。 |
| `3714b504` / #7782 | 管理页、HTTP 客户端与原生 IP 测试的 Clippy 清理 | 没有对应实现：本仓库没有上游管理后台、原生 HTTP 客户端和 IP 全量扫描测试；通过本仓库 `clippy --all-targets -D warnings` 确认本地目标。 |
| `1c89e177` / #7770 | 组织恢复自动启用邮箱 2FA 时要求已验证邮箱；统一 verified 判断 | 组织恢复/自动回退不适用。本地 Profile/Sync/API Key JWT 已使用持久化 `email_verified`，本次将普通登录和刷新 JWT 的硬编码 `true` 改为同一字段，保持验证状态一致。未引入上游 SMTP 假设。 |
| `f4f1a8e1` / #7806 | Send 旧接口清理、访问计数、访问响应 ID、轮换行为 | 已逻辑合入，保留本仓库 Turnstile 门禁、限流、D1 原子计数、R2 存储和通知。组织密码项查询补充条件不适用。 |
| `1f99d9d2` / #7809 | 清理旧接口和兼容字段、Android 请求兼容、账户和 2FA 校验 | 已合入适用后端变化；组织/SSO/Duo 改动不适用；旧 Web Vault CSS 清理由用户手动处理。 |

## 后端行为变化

### 账户及认证

- 移除 `POST /identity/accounts/register` 与 `POST /api/accounts/prelogin`；注册使用 `/identity/accounts/register/finish`，预登录使用 `/identity/accounts/prelogin` 或 `/identity/accounts/prelogin/password`。
- 注册完成请求执行 `UNAUTHENTICATED_LIMITER`，校验注册令牌的签名、有效期与规范化邮箱；从令牌读取姓名，限制 50 字节，忽略旧注册 body 中的 `name`。继续保留单用户检查、数据库单用户触发器及 `ALLOWED_EMAILS` 白名单。
- 注册响应改为 `{"object":"registerFinish"}`。注册和设置密码响应移除 `captchaBypassToken`；登录和 API Key 登录响应移除 `ResetMasterPassword`。
- 注册支持 Android 2026.9 的 `MasterPasswordAuthentication`、`MasterPasswordUnlock` 和认证对象中的 `Kdf`、`Salt`、`MasterPasswordAuthenticationHash`。原有 camelCase 及 Android 旧平铺格式继续支持；密码修改已有 PascalCase 兼容由回归测试确认。
- `/api/accounts/keys` 通过有条件的 D1 更新阻止覆盖任意已存在的公钥/私钥；设置初始密码同时检查已存在的私钥和密码哈希。
- 空白 `twoFactorToken` 按缺失处理；移除旧客户端登录时自动发送邮箱 2FA 码的分支，发送验证码继续由 `/api/two-factor/send-email-login` 发起。
- `/api/two-factor/disable` 仅保留 PUT。Authenticator/Email 禁用本来已经清除记住设备令牌；现在删除 WebAuthn 密钥的两个入口也执行清除。
- 邮箱 2FA 失败日志转义用户名，避免控制字符注入日志。
- 批量密码项操作的 ID 使用集合，避免重复删除同一项产生中途错误或重复副作用。

### Send

- 移除 `POST /api/sends/file`、`POST /api/sends/access/{access_id}`、`POST /api/sends/{send_id}/access/file/{file_id}` 及其旧处理器。保留文件 v2 创建/上传和 Bearer Send 令牌接口。
- 获取 Send 访问令牌只校验可用性与密码，不消耗访问次数或触发数据变更通知。
- 文本 Send 在 `POST /api/sends/access` 原子增加次数；文件 Send 在 `POST /api/sends/access/file/{file_id}` 原子增加次数。复用同一令牌也不能越过上限；文件元数据读取不计数。
- 文件下载地址申请先验证 Send 类型、加密文件元数据 ID 和 `send_files` 所有权；失败不会消耗次数。
- 匿名 `send-access` 响应的 `id` 改为链接使用的 base64url access ID；所有者管理响应仍使用 UUID。
- 密钥轮换只修改 Send 包装密钥和 revision，保留名称、密文、密码哈希、有效期、禁用状态、文件元数据及访问限制。缺失 Send ID 在任何轮换写操作前拒绝。
- 密钥轮换接口补齐 HeavyDo 分流，确保密码验证/哈希运行在 DO CPU 预算内。

## 用户需要手动处理的前端变化

1. **#7759 / `f9f011d5`**：禁止修改邮箱时隐藏整个区域（包括标题）。上游新增 `email_change_allowed` CSS 模板选项，以及 `div:has(> app-change-email)` 隐藏规则。
2. **#7809 / `1f99d9d2` 的 CSS 部分**：移除 2025.5.1 之前的 SSO/Passkey/分隔文字选择器和旧注册入口选择器，使用当前 `.vw-sso-login`、`.vw-passkey-login`、`.vw-or-text`、`app-root a[routerlink="/signup"]` 等规则。

上游对应 `src/api/web.rs` 与 `src/static/templates/scss/vaultwarden.scss.hbs`；本仓库的适配位置为 `src/handlers/css.rs` 及其配置。仅替换 `static/web-vault/` 不会更新 Worker 生成的 CSS。本仓库支持 Passkey 登录，请适配上游 CSS 意图时保留本地的登录能力及开关。

此次没有修改 `static/**`、`src/handlers/css.rs` 或 Web Vault 版本；这 10 次上游提交也没有 Web Vault 构建版本升级。

已静态核对当前 Web Vault 构建使用 `PUT /two-factor/disable`、`POST /accounts/register/finish` 和 Bearer `POST /sends/access/file/{id}`，与保留的后端接口一致。这项核对不代替真实浏览器端到端验证。

## 验证

- `cargo test --all-targets --locked`：77 passed。
- `node --test tests/*.test.mjs`：25 passed；新增 SQLite 行为测试验证 Send 轮换数据保留、访问上限原子更新和账户密钥初始化不可覆盖。
- `cargo clippy --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check` 和 `git diff --check`：通过。
- `worker-build --release`：通过，生成 Wasm/JS 发布产物。构建未运行前端补丁脚本。
- `wrangler deploy --dry-run`：通过，使用正式仓库配置识别 D1、R2、两个 DO、三个限流器及静态资源。其自定义构建触发了现有 Turnstile HTML 补丁；已核验只有脚本注入变化并将该文件恢复为任务开始时的内容，前端最终无差异。
- 在 `.wrangler/upstream-sync-2026-10-05/` 中使用隔离的本地 D1/R2/DO 与测试配置；先执行现有 schema 和 `0001_add_user_key_id.sql`，没有新增或修改数据库迁移。
- `node tests/upstream_compat_http.mjs http://127.0.0.1:8795`：46 次接口请求及额外的并发访问/R2 下载检查通过。覆盖接口清理、注册令牌与姓名来源、Android 请求格式、功能开关、账户密钥保护、文本 Send 5 次并发访问只允许 2 次、令牌复用上限、错误文件 ID 不计数、文件上传/下载计数、重复 Cipher ID 删除、轮换前校验、Send 密文/策略保留和 Android 密码修改后重新登录。
- 补充本地 API 验证：注册完成接口连续 60 次请求中的后 10 次返回 HTTP 429；两个 JWT 的邮箱验证状态跟随数据库；只有密码哈希而私钥为空时仍拒绝重新设置初始密码；单独存在公钥时拒绝覆盖；空密钥对只能初始化一次；两个 WebAuthn 删除入口均清除所有设备的记住令牌。相关测试数据仅写入隔离的本地数据库。

变更保留在当前工作区；未提交、推送或部署 Cloudflare，未执行真实 Bitwarden 客户端或浏览器端到端验证。
