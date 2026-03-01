# Warden Worker

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）作为数据存储，核心代码用 Rust 编写，目标是“个人可用、部署成本低、无需维护服务器”。

本项目不接触你的明文密码：Bitwarden系列客户端会在本地完成加密，服务端只保存密文数据。

## 功能

- 无服务器部署：Cloudflare Workers + D1 Sql + R2 存储桶
- 兼容多端：官方 Bitwarden（浏览器扩展 / 桌面 / 安卓）与多数第三方客户端
- 核心能力：注册/登录、同步、密码项（Cipher）增删改、文件夹、TOTP（Authenticator）二步验证、邮箱二步验证
- 官方安卓兼容：支持 `/api/devices/knowndevice` 与 remember-device 流程
- **安全增强**：支持"踢出所有已登录设备"，增强了 Token 刷新时的安全性
- **消息通知**：支持企业微信 Webhook 推送，覆盖登录/失败、密码库变更等 10+ 种事件，支持 GeoIP 显示 IP 归属地
- **邮箱二步验证**：通过 Webhook/Telegram 发送验证码邮件，无需配置 SMTP 服务器
- 性能优化：加密算法使用 CF 提供的函数，避免了 Rust 标准库的加密性能问题
- 强制使用Argon2id算法，避免CPU超时

## 自动部署（GitHub Actions）（推荐）

本项目已内置 GitHub Actions 工作流（`.github/workflows/push-cloudflare.yaml`），支持代码推送时自动构建并部署。

### 1. Fork 本项目
Fork 本仓库到你的 GitHub 账号。

### 2. 配置 Repository Secrets
在 GitHub 仓库的 **Settings** -> **Secrets and variables** -> **Actions** 中添加以下密钥：

| Secret Name | 说明 | 获取方式 |
| :--- | :--- | :--- |
| `CLOUDFLARE_API_TOKEN` | API 令牌 | Cloudflare 用户设置 -> API Tokens -> Create Token (模板选 Edit Cloudflare Workers) |
| `CLOUDFLARE_ACCOUNT_ID` | 账户 ID | Cloudflare Workers 首页右侧边栏 Account ID |
| `D1_DATABASE_ID` | D1 数据库 ID | `wrangler d1 info vaultsql` 或 Cloudflare D1 控制台 |

*** 在Cloudflare控制台创建D1数据库后，还需要执行 `sql/schema.sql`中的代码来初始化数据库。 ***
cloudflare dashboard -> 存储和数据库 -> D1 SQL 数据库 -> vaultsql -> 控制台 ->粘贴 `sql/schema.sql` 内容 -> 执行

### 3. 配置Cloudflare Workers运行环境密钥
在 Cloudflare Dashboard -> Workers -> Settings -> Variables 中手动添加以下机密变量。
```
JWT_SECRET
JWT_REFRESH_SECRET
ALLOWED_EMAILS
TWO_FACTOR_ENC_KEY
WEWORK_WEBHOOK_URL
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
TURNSTILE_SECRET_KEY
TURNSTILE_SITE_KEY
```
- **JWT_SECRET**：访问令牌签名密钥。用于签署短效 Access Token。**必须设置强随机字符串。**
- **JWT_REFRESH_SECRET**：刷新令牌签名密钥。用于签署长效 Refresh Token。**必须设置强随机字符串，且不要与 JWT_SECRET 相同。**
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在"数据库还没有任何用户"时启用），多个邮箱用英文逗号分隔。
- **TWO_FACTOR_ENC_KEY**：可选，Base64 的 32 字节密钥；用于加密存储 TOTP 秘钥
- **WEWORK_WEBHOOK_URL**：可选，企业微信群机器人的 Webhook 地址。用于事件通知和邮箱二步验证验证码发送。
- **TELEGRAM_BOT_TOKEN**：可选，Telegram Bot 的 Token。从 [@BotFather](https://t.me/BotFather) 获取。
- **TELEGRAM_CHAT_ID**：可选，接收通知的 Chat ID。可以是个人用户 ID、群组 ID 或频道 ID。通过 [@userinfobot](https://t.me/userinfobot) 获取个人 ID。
- **TURNSTILE_SECRET_KEY**：可选但建议开启，Cloudflare Turnstile 私钥；用于匿名访问 Send 时的人机验证。可以从 Cloudflare Dashboard -> 应用程序安全 -> Turnstile -> 密钥 中获取。
- **TURNSTILE_SITE_KEY**：可选但建议开启，Cloudflare Turnstile 站点密钥；用于匿名访问 Send 时的人机验证。可以从 Cloudflare Dashboard -> 应用程序安全 -> Turnstile -> 站点密钥 中获取。
**人机验证说明**：开启后，匿名用户访问 Send 时会要求完成人机验证，防止被刷D1和R2的额度。

### 可选：动态 vaultwarden.css（参考 Vaultwarden 方案）

Worker 已支持动态生成 `GET /css/vaultwarden.css`，可通过环境变量按需隐藏入口并附加自定义 CSS。

- `VW_CSS_SIGNUP_DISABLED`：是否隐藏注册入口（默认 `false`）
- `VW_CSS_SENDS_ALLOWED`：是否显示 Sends（默认 `true`）
- `VW_CSS_PASSWORD_HINTS_ALLOWED`：是否显示密码提示相关入口（默认 `true`）
- `VW_CSS_SSO_ENABLED`：是否启用 SSO 样式切换（默认 `false`）
- `VW_CSS_SSO_ONLY`：是否仅保留 SSO 登录流（默认 `false`）
- `VW_CSS_PASSKEY_2FA_SUPPORTED`：是否显示 Passkey 2FA 入口（默认 `false`）
- `VW_CSS_REMEMBER_2FA_DISABLED`：是否隐藏“记住 2FA 30 天”复选框（默认 `false`）
- `VW_CSS_MAIL_2FA_ENABLED`：是否启用 Email 2FA 入口（默认 `true`）
- `VW_CSS_MAIL_ENABLED`：是否启用邮件能力（默认 `true`，关闭时也会隐藏 Email 2FA）
- `VW_CSS_YUBICO_ENABLED`：是否显示 YubiKey OTP 2FA 入口（默认 `false`）
- `VW_CSS_EMERGENCY_ACCESS_ALLOWED`：是否显示紧急访问入口（默认 `true`）
- `VW_CSS_LOAD_USER_CSS`：是否加载自定义 CSS（默认 `true`）
- `VW_CSS_USER`：自定义 CSS 文本（可放到 Worker Secret，优先读取 Secret）

### 4. 部署
在 GitHub 仓库的 **Actions** 中触发工作流，即可自动部署到 Cloudflare Workers。

## 手动部署（wrangler 命令行）(极度不推荐)

### 0. 前置条件

- 良好的网络环境（**推荐国外**）
- Cloudflare 账号
- Node.js + Wrangler：`npm i -g wrangler`
- Rust 工具链（建议稳定版）
- [LLVM/Clang（用于编译 Rust 代码）](https://github.com/llvm/llvm-project/)
- 安装 worker-build：`cargo install worker-build`

### 1. 创建 D1 数据库

```bash
wrangler d1 create vaultsql
```

把输出的 `database_id` 写入 `wrangler.jsonc` 的 `d1_databases`。

并在 Cloudflare 中创建一个 R2 Bucket（例如 `warden-send-files`），将 bucket 名称写入 `wrangler.jsonc` 的 `r2_buckets`（`SEND_FILES_BUCKET` 绑定）。

另外请在 `wrangler.jsonc` 配置 `ratelimits`（示例中使用 `SEND_ACCESS_LIMITER`）用于匿名 Send 访问限流；`namespace_id` 需要在你的账号内保持唯一，可按需调整 `limit/period`。

### 2. 初始化数据库

注意：`sql/schema.sql` 会 `DROP TABLE`，用于全新部署（会清空数据，**请注意导出密码库**）。

```bash
wrangler d1 execute vaultsql --remote --file=sql/schema.sql
```

### 3. 配置密钥（Secrets）

为了保证安全性，请务必设置强密码。

```bash
wrangler secret put JWT_SECRET
wrangler secret put JWT_REFRESH_SECRET
wrangler secret put ALLOWED_EMAILS
wrangler secret put DOMAIN
wrangler secret put TWO_FACTOR_ENC_KEY
wrangler secret put WEWORK_WEBHOOK_URL
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
wrangler secret put TURNSTILE_SECRET_KEY
```

- **JWT_SECRET**：访问令牌签名密钥。用于签署短效 Access Token。**必须设置强随机字符串。**
- **JWT_REFRESH_SECRET**：刷新令牌签名密钥。用于签署长效 Refresh Token。**必须设置强随机字符串，且不要与 JWT_SECRET 相同。**
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在"数据库还没有任何用户"时启用），多个邮箱用英文逗号分隔。
- **DOMAIN**：**必选**，你的服务域名，格式如 `https://vault.example.com`。用于 WebAuthn 安全密钥注册等功能。
- **TWO_FACTOR_ENC_KEY**：可选，Base64 的 32 字节密钥；用于加密存储 TOTP 秘钥（不设置则以 `plain:` 形式存储）。
- **WEWORK_WEBHOOK_URL**：可选，企业微信群机器人的 Webhook 地址（形如 `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...`）。用于事件通知和邮箱二步验证验证码发送。
- **TELEGRAM_BOT_TOKEN**：可选，Telegram Bot 的 Token。从 [@BotFather](https://t.me/BotFather) 获取。
- **TELEGRAM_CHAT_ID**：可选，接收通知的 Chat ID。可以是个人用户 ID、群组 ID 或频道 ID。通过 [@userinfobot](https://t.me/userinfobot) 获取个人 ID。
- **TURNSTILE_SECRET_KEY**：可选但建议开启，Cloudflare Turnstile 私钥；用于匿名访问 Send 时的人机验证。

### 4. 配置通知（可选但建议）

在 `wrangler.jsonc` 的 `vars` 字段中配置 `NOTIFY_EVENTS` 变量，以控制是否发送通知。默认 `"all"`。

### 5. 部署

```bash
wrangler deploy
```

部署后，把 Workers URL 或自定义域名填入 Bitwarden 客户端的“自托管服务器 URL”。

### 6. 升级
> 如果你曾经部署过旧版本并准备升级，建议在客户端 **导出密码库**  → **重新部署本项目（全新初始化数据库）** → **再导入密码库（可显著降低迁移/兼容成本）**。

## 客户端使用建议

- 官方安卓如果之前指向过其它自托管地址，建议“删除账号/清缓存后重新添加服务器”，避免 remember token 跨服务端复用导致登录失败。
- 首次启用 TOTP 后，建议在同一台设备上完成一次“输入 TOTP 登录”，后续官方安卓会自动走 remember-device。
- 如果你在网页端点击了“踢出所有设备”，所有已登录的客户端将在下次尝试刷新 Token 时（通常 2 小时内）被迫登出，需要重新登录。

## 已实现的关键接口（完整列表）

### 配置与探测
- `GET /api/config` - 获取服务配置
- `GET /api/alive` - 健康检查
- `GET /api/now` - 获取服务器当前时间
- `GET /api/version` - 获取版本号
- `GET /css/vaultwarden.css` - 动态生成 CSS（支持自定义主题）
- `GET /icons/{*path}` - 获取网站图标

### 账户与认证
- `POST /identity/accounts/prelogin` - 预登录（获取 KDF 参数）
- `POST /identity/connect/token` - 获取访问令牌
- `POST /identity/accounts/register/finish` - 完成注册
- `POST /identity/accounts/register/send-verification-email` - 发送注册验证邮件
- `GET /api/accounts/profile` - 获取账户资料
- `POST/PUT /api/accounts/profile` - 更新账户资料
- `PUT/POST /api/accounts/avatar` - 更新头像
- `POST /api/accounts/security-stamp` - 更新安全戳（踢出所有设备）
- `GET /api/accounts/revision-date` - 获取最后修改时间
- `POST /api/accounts/password-hint` - 获取密码提示
- `POST /api/accounts/prelogin` - 预登录（兼容路径）
- `POST /api/accounts/request-otp` - 请求 OTP
- `POST /api/accounts/verify-otp` - 验证 OTP
- `POST /api/accounts/verify-password` - 验证密码
- `PUT /api/accounts/password` - 修改主密码
- `PUT /api/accounts/email` - 修改邮箱
- `POST /api/accounts/kdf` - 更新 KDF 设置

### 设备管理
- `GET /api/devices` - 获取设备列表
- `GET /api/devices/identifier/{id}` - 根据标识获取设备
- `GET /api/devices/knowndevice` - 检查已知设备（官方安卓兼容）
- `PUT/POST /api/devices/identifier/{id}/token` - 更新设备令牌
- `PUT/POST /api/devices/identifier/{id}/clear-token` - 清除设备令牌

### 两步验证（2FA）
- `GET /api/two-factor` - 获取 2FA 状态
- `POST /api/two-factor/get-authenticator` - 获取身份验证器配置
- `POST/PUT/DELETE /api/two-factor/authenticator` - 启用/禁用身份验证器
- `POST /api/two-factor/authenticator/request` - 请求身份验证器验证码
- `POST /api/two-factor/authenticator/enable` - 启用身份验证器
- `POST /api/two-factor/authenticator/disable` - 禁用身份验证器
- `POST /api/two-factor/get-email` - 获取邮箱 2FA 配置
- `POST /api/two-factor/send-email` - 发送验证邮件
- `PUT/DELETE /api/two-factor/email` - 验证/禁用邮箱 2FA
- `POST/PUT /api/two-factor/disable` - 通用禁用 2FA
- `POST /api/two-factor/get-recover` - 获取恢复代码
- `POST /api/two-factor/recover` - 使用恢复码恢复
- `POST /two-factor/send-email-login` - 登录时发送验证码
- `POST /api/two-factor/send-email-login` - 登录时发送验证码（API 路径）
- `POST /api/two-factor/get-webauthn` - 获取 WebAuthn 配置
- `POST /api/two-factor/get-webauthn-challenge` - 获取 WebAuthn 挑战
- `POST/PUT/DELETE /api/two-factor/webauthn` - WebAuthn 管理

### WebAuthn 安全密钥
- `GET/POST /accounts/webauthn/assertion-options` - 获取断言选项
- `GET/POST /identity/accounts/webauthn/assertion-options` - 获取断言选项（兼容路径）
- `GET/POST /api/webauthn` - 列出/创建凭证
- `POST /api/webauthn/attestation-options` - 获取注册选项
- `POST /api/webauthn/prf-probe` - PRF 探测
- `POST /api/webauthn/assertion-options` - 获取断言选项
- `PUT /api/webauthn/{credential_id}` - 更新凭证
- `POST /api/webauthn/{credential_id}/delete` - 删除凭证

### 数据同步
- `GET /api/sync` - 完整同步密码库
- `POST /api/ciphers/import` - 导入数据

### 密码项（Ciphers）管理
- `POST /api/ciphers/create` - 创建密码项
- `POST /api/ciphers` - 批量创建密码项
- `DELETE /api/ciphers` - 批量硬删除密码项
- `PUT /api/ciphers/{id}` - 更新密码项
- `DELETE /api/ciphers/{id}` - 硬删除密码项
- `PUT/POST /api/ciphers/{id}/delete` - 软删除/硬删除密码项
- `PUT /api/ciphers/{id}/restore` - 恢复密码项
- `PUT/POST /api/ciphers/delete` - 批量软删除/硬删除
- `PUT /api/ciphers/restore` - 批量恢复密码项

### 文件夹管理
- `POST /api/folders` - 创建文件夹
- `PUT /api/folders/{id}` - 更新文件夹
- `DELETE /api/folders/{id}` - 删除文件夹

### Send 文件共享
- `GET /api/sends` - 获取 Send 列表
- `POST /api/sends` - 创建 Send
- `POST /api/sends/file/v2` - 创建文件 Send
- `POST /api/sends/access/{access_id}` - 访问 Send
- `GET /api/sends/{send_id}` - 获取 Send 详情
- `PUT /api/sends/{send_id}` - 更新 Send
- `DELETE /api/sends/{send_id}` - 删除 Send
- `PUT /api/sends/{send_id}/remove-password` - 移除 Send 密码
- `POST /api/sends/{send_id}/access/file/{file_id}` - 访问文件
- `GET /api/sends/{send_id}/{file_id}` - 下载文件
- `POST /api/sends/{send_id}/file/{file_id}` - 上传文件（最大 1024MB）
- `POST /sends/{send_id}/file/{file_id}` - 上传文件（兼容路径）
- `GET /send-verify` - Turnstile 验证页面
- `POST /api/send-verify` - Turnstile 验证

### 设置与兼容性
- `GET/POST/PUT /api/settings/domains` - 获取/更新域名设置
- `GET /api/collections` - 获取集合列表（兼容 Vaultwarden，返回空数组）
- `GET /api/policies` - 获取策略列表（兼容 Vaultwarden，返回空数组）
- `GET /api/organizations` - 获取组织列表（兼容 Vaultwarden，返回空数组）

### 使用统计
- `GET /api/d1/usage` - 获取 D1 数据库使用统计

### 认证请求（Admin Request）
- `GET/POST /api/auth-requests` - 获取/创建认证请求
- `POST /api/auth-requests/admin-request` - 创建管理员认证请求
- `GET /api/auth-requests/pending` - 获取待处理认证请求
- `GET/PUT /api/auth-requests/{id}` - 获取/更新认证请求
- `GET /api/auth-requests/{id}/response` - 获取认证请求响应

## 🔔 消息通知

本项目支持通过企业微信群机器人或 Telegram Bot 推送关键事件通知。两种方式可同时配置，也可任选其一。

### 1. 配置 Webhook

#### 企业微信
在 Cloudflare 后台或通过 wrangler 设置密钥 `WEWORK_WEBHOOK_URL`：
```bash
wrangler secret put WEWORK_WEBHOOK_URL
# 输入形如 https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxx 的地址
```

#### Telegram
```bash
wrangler secret put TELEGRAM_BOT_TOKEN
# 输入从 @BotFather 获取的 Bot Token

wrangler secret put TELEGRAM_CHAT_ID
# 输入接收通知的 Chat ID（个人 ID、群组 ID 或频道 ID）
```

**获取 Chat ID：**
- 个人 ID：向 [@userinfobot](https://t.me/userinfobot) 发送消息即可获取
- 群组/频道 ID：将 Bot 加入后，访问 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查看

### 2. 配置通知开关
在 `wrangler.jsonc` 的 `vars` 中修改 `NOTIFY_EVENTS` 环境变量来控制发送哪些通知。

- **开启所有**：`"NOTIFY_EVENTS": "all"`
- **关闭所有**：`"NOTIFY_EVENTS": "none"`
- **按需开启**：逗号分隔，例如 `"NOTIFY_EVENTS": "login,login_failed,cipher_delete"`

**支持的事件列表：**
- `login`：登录成功
- `login_failed`：登录失败（密码错误、用户不存在、2FA 错误）
- `password_hint`：密码提示（调用 `/api/accounts/password-hint` 时触发）
- `password`：修改主密码
- `email`：修改邮箱
- `kdf`：修改 KDF 设置
- `cipher_create`：新增密码项
- `cipher_update`：修改密码项
- `cipher_delete`：删除密码项（含软删除/恢复/彻底删除）
- `import`：导入数据
- `send_create` / `send_delete`：Send 创建与删除
- `2fa_enable` / `2fa_disable` / `2fa_recover`：两步验证变更与恢复

**特性：**
- **GeoIP**：自动识别并显示操作 IP 的归属地（国家/地区/城市）。
- **美化模版**：使用 Markdown 格式，支持 Emoji 与关键信息高亮。
- **时区**：时间自动转换为 UTC+8（北京时间）。

## 📧 邮箱二步验证

本项目支持邮箱二步验证（Email 2FA），验证码通过企业微信 Webhook 或 Telegram Bot 发送通知。

### 1. 配置 Webhook

邮箱二步验证使用与事件通知相同的 Webhook 配置（企业微信和 Telegram 均可），无需额外配置。

**企业微信：**
```bash
wrangler secret put WEWORK_WEBHOOK_URL
# 输入形如 https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxx 的地址
```

**Telegram：**
```bash
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
```

### 2. 验证码通知格式

验证码会以企业微信 Markdown 消息格式发送：

```
# 📧 Warden Worker 验证码
> 🕒 时间：2026-02-22 10:30:00
> 📧 邮箱：user@example.com

您的验证码是：**123456**

验证码有效期为10分钟，请尽快完成验证。
```

### 3. 已实现的接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/two-factor` | GET | 获取 2FA 状态列表 |
| `/api/two-factor/get-authenticator` | POST | 获取身份验证器配置 |
| `/api/two-factor/authenticator` | POST/PUT | 启用身份验证器 2FA |
| `/api/two-factor/authenticator` | DELETE | 禁用身份验证器 2FA |
| `/api/two-factor/get-email` | POST | 获取当前邮箱 2FA 配置状态 |
| `/api/two-factor/send-email` | POST | 发送验证邮件到指定邮箱 |
| `/api/two-factor/email` | PUT | 验证邮箱并启用邮箱 2FA |
| `/api/two-factor/email` | DELETE | 禁用邮箱 2FA |
| `/api/two-factor/disable` | POST/PUT | 通用禁用 2FA 端点（支持 type 参数） |
| `/api/two-factor/get-recover` | POST | 获取两步验证恢复代码 |
| `/api/two-factor/recover` | POST | 使用恢复码恢复账户（删除所有 2FA） |
| `/two-factor/send-email-login` | POST | 登录时发送验证码邮件 |
| `/api/two-factor/send-email-login` | POST | 登录时发送验证码邮件（API 路径） |

### 4. 使用流程

1. 用户在客户端设置页面选择"邮箱二步验证"
2. 输入要接收验证码的邮箱地址
3. 系统通过企业微信 Webhook 发送验证码通知
4. 用户输入收到的验证码完成验证
5. 邮箱二步验证启用成功

## 许可证

MIT
