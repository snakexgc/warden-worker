# Warden Worker

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）作为数据存储，核心代码用 Rust 编写，目标是“个人可用、部署成本低、无需维护服务器”。

本项目不接触你的明文密码：Bitwarden系列客户端会在本地完成加密，服务端只保存密文数据。

# 特别注意
建议 Fork 本项目到你的 GitHub 账号；使用私有镜像仓库也可以，但必须保留本项目的 Workflow，并在仓库设置中允许 GitHub Actions 运行。Workflow 已显式申请私有仓库检出所需的 `contents: read` 权限。

## 功能

- 无服务器部署：Cloudflare Workers + D1 Sql + R2 存储桶
- 兼容多端：官方 Bitwarden（浏览器扩展 / 桌面 / 安卓）与多数第三方客户端
- 核心能力：注册/登录、同步、密码项（Cipher）增删改、文件夹、TOTP（Authenticator）二步验证、邮箱二步验证
- 官方安卓兼容：支持 `/api/devices/knowndevice` 与 remember-device 流程
- **安全增强**：支持"踢出所有已登录设备"，增强了 Token 刷新时的安全性
- **消息通知**：支持企业微信 Webhook 推送，覆盖登录/失败、密码库变更等 10+ 种事件，支持 GeoIP 显示 IP 归属地
- **邮箱二步验证**：通过 Webhook/Telegram 发送验证码邮件，无需配置 SMTP 服务器
- 性能优化：加密算法使用 CF 提供的函数，避免了 Rust 标准库的加密性能问题

## 自动部署（GitHub Actions）（推荐）

本项目已内置 GitHub Actions 工作流（`.github/workflows/push-cloudflare.yaml`），同时支持全新部署和后续自动升级。只要 API Token 仅授权给一个 Cloudflare 账户，配置一个 GitHub Secret 后即可无人值守完成资源创建、数据库初始化、构建、迁移、部署和健康检查。

### 1. Fork 本项目
Fork 本仓库到你的 GitHub 账号。

### 2. 配置 Repository Secrets
在 GitHub 仓库的 **Settings** -> **Secrets and variables** -> **Actions** 中添加以下密钥：

| Secret Name | 说明 | 获取方式 |
| :--- | :--- | :--- |
| `CLOUDFLARE_API_TOKEN` | **必选**，Cloudflare API Token（不是 Global API Key） | Cloudflare 用户设置 -> API Tokens -> Create Token |
| `CLOUDFLARE_ACCOUNT_ID` | 可选；仅当同一 Token 能访问多个账户时用于消除歧义 | Cloudflare Workers 首页右侧边栏 Account ID |

#### 创建 API Token 的详细步骤

1. 访问 [Cloudflare API Tokens 页面](https://dash.cloudflare.com/profile/api-tokens)
2. 点击 **"Create Token"** 按钮
3. 选择 **"Create Custom Token"**（自定义令牌）
4. 填写以下配置：

**Token name**: `warden-worker-deploy`（可自定义）

**Permissions**（权限配置 - 必须包含以下所有权限）:

| 类别 | 权限 | 说明 |
|------|------|------|
| **Account** | `Workers Scripts` > `Edit` | 部署和管理 Workers 脚本 |
| **Account** | `Account Settings` > `Read` | 读取账户信息 |
| **Account** | `D1` > `Edit` | 创建和管理 D1 数据库 |
| **Account** | `Workers R2 Storage` > `Edit` | 创建和管理 R2 Bucket |

**Account Resources**：选择目标账户，且建议只选择这一个账户。这样工作流可直接从 Token 自动发现 Account ID，无需配置 `CLOUDFLARE_ACCOUNT_ID`。

**Zone Resources**: 保持为空（除非你需要管理特定 Zone）

5. 点击 **"Continue to summary"** 确认权限
6. 点击 **"Create Token"** 生成令牌
7. **立即复制 Token** 并保存到 GitHub Secrets（Token 只会显示一次）

> ⚠️ **重要提示**：
> - 必须包含所有上述权限，否则 wrangler CLI 可能报错
> - 工作流只接受 API Token；旧式 Global API Key 还需要账户邮箱，不能满足单 Secret 的无人值守部署要求
> - 如果 Token 能访问多个账户，工作流会安全停止；请把 Token 的 Account Resources 限定为目标账户，或额外添加 `CLOUDFLARE_ACCOUNT_ID`
> - Token 应妥善保管，泄露后需立即撤销并重新创建

#### 可选：获取 Account ID

只有 Token 能访问多个账户且不便重新限定资源范围时，才需要配置此项：

1. 访问 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 在首页右侧边栏找到 **Account ID**
3. 或者访问 [Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages) 页面，左侧会显示账户 ID

### 3. 首次部署（自动创建基础设施）

首次部署时，GitHub Actions 工作流会自动：
- ✅ 从 API Token 自动发现并验证唯一的 Cloudflare Account ID
- ✅ 在账户尚无 Workers 子域时创建一个确定性的 `workers.dev` 子域，避免 Wrangler 交互提示
- ✅ 检查 D1 数据库 `vaultsql` 是否存在，不存在则自动创建
- ✅ 自动执行 `sql/schema.sql` 初始化数据库（仅首次），随后应用 `sql/migrations` 中尚未执行的增量迁移
- ✅ 检查 R2 Bucket `warden-send-files` 是否存在，不存在则自动创建
- ✅ 将 Cloudflare 返回的真实 `database_id` 精确写入 `wrangler.jsonc` 的 `vaultsql` 绑定并再次校验
- ✅ 完成 Rust/Node 测试、release dry-run、Durable Objects 初始化和 Worker 部署
- ✅ 重试检查根 `/alive`，确认 Worker 与 D1 都可访问

> 💡 **提示**：整个过程全自动，无需手动创建数据库或配置 ID！

资源查找全部使用精确名称匹配，不再从 Wrangler 的人类可读文本中 `grep` UUID；API 或权限错误也不会被当成“资源不存在”。仓库中原有的 `database_id` 只用于本地开发，Actions 每次都会用目标账户中 `vaultsql` 的真实 ID 覆盖当前 runner 的配置，不会把该临时值提交回仓库。

### 4. 后续自动升级

推送到 `main`、`uat` 或 `release*` 分支会自动触发部署；也可以从 Actions 页面手动触发。所有分支共用同一部署队列，新的运行不会取消正在执行的数据库迁移：

1. 精确复用已有 D1、R2 和 Workers 子域，不执行 `schema.sql`。
2. 先完成测试和 Worker release dry-run。
3. 按顺序执行 `sql/migrations` 中尚未记录到 `d1_migrations` 的 SQL。
4. 迁移成功后部署新 Worker；失败则不部署依赖新结构的代码。
5. Wrangler 根据 `wrangler.jsonc` 原生处理 Durable Objects；工作流不会直接 PATCH 或删除 DO 绑定和数据。

> 2026-07-22 统一基线之前创建的旧数据库，仍需先按下文“升级”章节完成一次手动基线对齐。全新数据库以及已经对齐的数据库不需要人工参与。

### 5. 可选：配置 Cloudflare Workers 运行环境密钥
基础密码库不依赖以下密钥即可运行。只有需要注册白名单、Turnstile 或 Webhook/Telegram/企业微信通知时，才在 Cloudflare Dashboard -> Workers -> Settings -> Variables 中添加对应机密变量。
```
ALLOWED_EMAILS
WEWORK_WEBHOOK_URL
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
TURNSTILE_SECRET_KEY
TURNSTILE_SITE_KEY
```
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在"数据库还没有任何用户"时启用），多个邮箱用英文逗号分隔。
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

紧急访问、Duo 与 YubiKey OTP 的服务端配置：

- `EMERGENCY_ACCESS_ALLOWED`：是否启用紧急访问 API，默认 `true`；等待期由现有每 5 分钟 Cron 推进。
- Duo 全局配置使用 Secrets `DUO_HOST`、`DUO_IKEY`、`DUO_SKEY`、`DUO_AKEY`。用户也可以保存自己的 Host/IKey/SKey，但签名登录仍要求服务器级 `DUO_AKEY`。
- YubiKey OTP 使用 Secrets `YUBICO_CLIENT_ID`、`YUBICO_SECRET_KEY`；可选 `YUBICO_SERVER`，默认使用 Yubico OTP 2.0 官方 HTTPS 端点。
- 配置外部二步验证 Secrets 后，再分别开启 `VW_CSS_DUO_ENABLED`、`VW_CSS_YUBICO_ENABLED`，以在 Web Vault 中显示入口。
- `VW_CSS_LOAD_USER_CSS`：是否加载自定义 CSS（默认 `true`）
- `VW_CSS_USER`：自定义 CSS 文本（可放到 Worker Secret，优先读取 Secret）

### 6. 部署
保存 `CLOUDFLARE_API_TOKEN` 后，在 GitHub 仓库的 **Actions** 中手动运行一次工作流；此后上述分支每次出现新提交都会自动升级部署。

> 💡 **提示**：首次部署可能需要 3-5 分钟，因为包含构建和基础设施创建过程。

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
wrangler d1 migrations apply vaultsql --remote
```

### 3. 配置密钥（Secrets）

为了保证安全性，JWT 密钥现在会自动生成并存储在 D1 数据库中，无需手动配置。

```bash
wrangler secret put ALLOWED_EMAILS
wrangler secret put DOMAIN
wrangler secret put WEWORK_WEBHOOK_URL
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
wrangler secret put TURNSTILE_SECRET_KEY
```

- **ALLOWED_EMAILS**：首个账号注册白名单（仅在"数据库还没有任何用户"时启用），多个邮箱用英文逗号分隔。
- **DOMAIN**：可选的公开域名覆盖，格式如 `https://vault.example.com`；未设置时附件和 Send 使用相对 URL，WebAuthn 从当前请求头确定安全来源。
- **WEWORK_WEBHOOK_URL**：可选，企业微信群机器人的 Webhook 地址（形如 `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...`）。用于事件通知和邮箱二步验证验证码发送。
- **TELEGRAM_BOT_TOKEN**：可选，Telegram Bot 的 Token。从 [@BotFather](https://t.me/BotFather) 获取。
- **TELEGRAM_CHAT_ID**：可选，接收通知的 Chat ID。可以是个人用户 ID、群组 ID 或频道 ID。通过 [@userinfobot](https://t.me/userinfobot) 获取个人 ID。
- **TURNSTILE_SECRET_KEY**：可选但建议开启，Cloudflare Turnstile 私钥；用于匿名访问 Send 时的人机验证。

### 4. 配置通知（可选但建议）

在 `wrangler.jsonc` 的 `vars` 字段中配置 `NOTIFY_EVENTS` 变量，以控制是否发送通知。默认 `"all"`。

### 5. 部署

本次从旧版本升级时，请先按第 6 节手动把 D1 对齐到 2026-07-22 基线，再部署 Worker。完成这次对齐后，后续数据库升级由 GitHub Actions 在 Worker 部署前自动应用 `sql/migrations` 中尚未执行的增量迁移。

```bash
wrangler deploy
```

部署后，把 Workers URL 或自定义域名填入 Bitwarden 客户端的“自托管服务器 URL”。

### 6. 升级
> `sql/schema.sql` 是 2026-07-22 统一后的完整数据库基线。它会删除并重建全部项目表，同时清除 Wrangler 的 `d1_migrations` 记录；执行后现有 D1 数据不可恢复。本次基线对齐不提供原地升级兼容。

手动升级步骤：

1. 在 Bitwarden 客户端导出密码库，并按需另行备份 D1/R2。
2. 用当前基线重建远程 D1：

   ```bash
   wrangler d1 execute vaultsql --remote --file=sql/schema.sql
   ```

3. 部署当前 Worker，再把密码库导回客户端。完成后即可恢复使用 GitHub Actions 自动部署。

当前基线已经合并全部历史数据库变更，包括 Argon2 KDF 字段、服务端密码哈希字段、账号兼容字段、单用户约束、设备与认证请求、TOTP 防重放时间步、Email/WebAuthn 2FA、归档、附件以及 Send 的 D1/R2 元数据。旧迁移已经删除，`sql/d1-migrations` 目录也不再使用。

#### 后续数据库变更

统一基线之后的每次数据库变更只新增到 `sql/migrations`。使用 Wrangler 创建顺序迁移：

```bash
wrangler d1 migrations create vaultsql add_example_column
```

生成的文件形如 `sql/migrations/0001_add_example_column.sql`。写入并在本地验证 SQL 后随代码提交；GitHub Actions 会在部署 Worker 之前执行：

```bash
wrangler d1 migrations apply vaultsql --remote
```

Wrangler 使用 D1 的 `d1_migrations` 表记录已执行的文件，因此后续部署只会应用尚未执行的迁移。新数据库会先导入 `sql/schema.sql` 基线，再依次执行 `sql/migrations` 中的全部迁移；已有数据库只执行待处理迁移。迁移失败会使基础设施任务失败，从而阻止依赖新结构的 Worker 继续部署。

已经应用的迁移不得修改、改名、重排或删除。为了避免新数据库重复创建同一结构，基线之后的变化不要同时写回 `sql/schema.sql`；需要再次收敛基线时，应单独安排一次和本次相同的手动重建。

密码项独立加密密钥、用户 API Key 与待确认邮箱字段、附件元数据表均已直接包含在 `sql/schema.sql` 中。附件二进制数据仍存储在既有的 `SEND_FILES_BUCKET` R2 Bucket；`wrangler.jsonc` 中的每日 Cron 会清理已过删除日期的 Send，避免 D1 元数据与 R2 文件长期残留。

附件和文件 Send 的单文件上限固定为 **95 MiB**。上传请求体上限为 100,000,000 字节，以适配 Cloudflare Free/Pro 的 100 MB 入口限制并给 multipart 边界留出余量；文件数据按约 8 MiB 分片写入 R2，下载通过 Cloudflare `FixedLengthStream` 直接流式返回并生成正确的 `Content-Length`，不会把完整文件读入 Worker 内存。

密码迁移不会立即改写现有密码哈希。旧记录会在用户下一次成功输入主密码时自动迁移为独立的 PBKDF2-HMAC-SHA256（600,000 次迭代、64 字节随机 salt）；客户端 KDF 设置保持不变。单用户迁移会阻止继续向 `users` 表插入记录，但不会删除或修改已有用户。注册接口也会在检测到首个用户后立即返回错误，不再执行耗时的密码哈希。

服务端 PBKDF2 使用 Rust/Wasm 实现，以避开 Workers Web Crypto 单次最多 100,000 次迭代的限制。所有创建或验证服务端密码哈希的接口（注册、登录、主密码/邮箱/KDF 修改、密码确认、账号删除、设置密码，以及可能验证主密码的双因素和 WebAuthn 接口）都由 `HEAVY_DO` 承载：Free 计划的入口 Worker 只负责轻量路由，实际 600,000 次 PBKDF2 在每次调用默认具有 30 秒 CPU 上限的 Durable Object 内执行。本项目定位为个人单用户密码库，所有重计算路由共用一个固定名称为 `personal-vault` 的 `HeavyDo` 实例，不按用户或请求创建额外实例；代价是同时发生的重计算会短暂串行，但个人使用场景下可以接受。Free 计划仍需遵守 Durable Objects 的每日请求量和 duration 配额；限制详情参见 [Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/) 与 [pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)。

## 组织功能（试运行）

组织核心能力可以运行在 Cloudflare Workers 上：成员、集合、组、策略、事件和共享密码项元数据存入 D1；附件继续使用 R2；密码哈希和组织管理请求由按身份稳定分片的 `HeavyDo` 承载；邀请注册链接通过内部 Webhook/Telegram outbox 投递并由 Cron 重试。

组织功能默认关闭。启用前应按以下顺序操作：

1. 备份 D1 和 R2，并先执行 `wrangler d1 migrations apply vaultsql --remote`。
2. 至少配置 `WEWORK_WEBHOOK_URL`，或同时配置 `TELEGRAM_BOT_TOKEN` 与 `TELEGRAM_CHAT_ID`，验证注册和组织邀请链接能够送达。
3. 先在测试环境把 `ORGANIZATIONS_ENABLED` 改为 `true`，完成创建组织、邀请/确认成员、集合授权、共享密码项和全量同步测试。
4. 组和事件分别由 `ORG_GROUPS_ENABLED`、`ORG_EVENTS_ENABLED` 控制；核心组织流程稳定后再分别开启。

Workers/D1 没有阻碍核心组织功能，但存在平台边界：导入和批量接口按 40 条 D1 语句分批，组织导入最多 500 个密码项和 500 个集合，跨批导入不是单个数据库事务。当前仍不支持组织密码项附件、组织 API Key/客户端凭据、SSO/SCIM、Provider，以及完整的服务端组织操作事件审计；在这些能力补齐前不要把本实现视为 Vaultwarden 企业功能的完全替代。

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
