# Warden Worker

# 有问题？尝试 [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/snakexgc/warden-worker)

Warden Worker 是一个运行在 Cloudflare Workers 上的轻量级 Bitwarden 兼容服务端实现，使用 Cloudflare D1（SQLite）作为数据存储，核心代码用 Rust 编写，目标是“个人/家庭可用、部署成本低、无需维护服务器”。

本项目不接触你的明文密码：Bitwarden 系列客户端会在本地完成加密，服务端只保存密文数据。


## 功能

- 无服务器部署：Cloudflare Workers + D1
- 兼容多端：官方 Bitwarden（浏览器扩展 / 桌面 / 安卓）与多数第三方客户端
- 核心能力：注册/登录、同步、密码项（Cipher）增删改、文件夹、TOTP（Authenticator）二步验证
- 官方安卓兼容：支持 `/api/devices/knowndevice` 与 remember-device（twoFactorProvider=5）流程
- **安全增强**：支持“踢出所有已登录设备”（Security Stamp 校验），增强了 Token 刷新时的安全性
- **消息通知**：支持企业微信 Webhook 推送，覆盖登录/失败、密码库变更等 10+ 种事件，支持 GeoIP 显示 IP 归属地

## 手动部署（wrangler 命令行）

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
wrangler secret put TWO_FACTOR_ENC_KEY
wrangler secret put WEWORK_WEBHOOK_URL
```

- **JWT_SECRET**：访问令牌签名密钥。用于签署短效 Access Token。**必须设置强随机字符串。**
- **JWT_REFRESH_SECRET**：刷新令牌签名密钥。用于签署长效 Refresh Token。**必须设置强随机字符串，且不要与 JWT_SECRET 相同。**
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在“数据库还没有任何用户”时启用），多个邮箱用英文逗号分隔。
- **TWO_FACTOR_ENC_KEY**：可选，Base64 的 32 字节密钥；用于加密存储 TOTP 秘钥（不设置则以 `plain:` 形式存储）。
- **WEWORK_WEBHOOK_URL**：可选，企业微信群机器人的 Webhook 地址（形如 `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...`）。

### 4. 配置通知（可选）

在 `wrangler.jsonc` 的 `vars` 字段中配置 `NOTIFY_EVENTS` 变量，以控制是否发送通知。默认 `"all"`。

### 5. 部署

```bash
wrangler deploy
```

部署后，把 Workers URL 或自定义域名（例如 `https://key.snakexgc.com`）填入 Bitwarden 客户端的“自托管服务器 URL”。

### 6. 升级
> 如果你曾经部署过旧版本并准备升级，建议在客户端 **导出密码库**  → **重新部署本项目（全新初始化数据库）** → **再导入密码库（可显著降低迁移/兼容成本）**。

## 自动部署（GitHub Actions）

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
*** 控制台创建D1数据库后，还需要在执行 `sql/schema.sql`中的代码来初始化数据库。 ***

### 3. 配置Cloudflare Workers运行环境密钥
在 Cloudflare Dashboard -> Workers -> Settings -> Variables 中手动添加以下五个机密变量。
```
JWT_SECRET
JWT_REFRESH_SECRET
ALLOWED_EMAILS
TWO_FACTOR_ENC_KEY
WEWORK_WEBHOOK_URL
```
- **JWT_SECRET**：访问令牌签名密钥。用于签署短效 Access Token。**必须设置强随机字符串。**
- **JWT_REFRESH_SECRET**：刷新令牌签名密钥。用于签署长效 Refresh Token。**必须设置强随机字符串，且不要与 JWT_SECRET 相同。**
- **ALLOWED_EMAILS**：首个账号注册白名单（仅在“数据库还没有任何用户”时启用），多个邮箱用英文逗号分隔。
- **TWO_FACTOR_ENC_KEY**：可选，Base64 的 32 字节密钥；用于加密存储 TOTP 秘钥
- **WEWORK_WEBHOOK_URL**：可选，企业微信群机器人的 Webhook 地址。
可以使用PowerShell生成 TWO_FACTOR_ENC_KEY ：
```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object {Get-Random -Minimum 0 -Maximum 256}))
```
### 4. 部署
在 GitHub 仓库的 **Actions** 中触发工作流，即可自动部署到 Cloudflare Workers。

## 客户端使用建议

- 官方安卓如果之前指向过其它自托管地址，建议“删除账号/清缓存后重新添加服务器”，避免 remember token 跨服务端复用导致登录失败。
- 首次启用 TOTP 后，建议在同一台设备上完成一次“输入 TOTP 登录”，后续官方安卓会自动走 remember-device（provider=5）。
- 如果你在网页端点击了“踢出所有设备”，所有已登录的客户端将在下次尝试刷新 Token 时（通常 2 小时内）被迫登出，需要重新登录。

## 已实现的关键接口（部分）

- 配置与探测：`GET /api/config`、`GET /api/alive`、`GET /api/now`、`GET /api/version`
- 登录：`POST /identity/accounts/prelogin`、`POST /identity/connect/token`
- 账户安全：`POST /api/accounts/security-stamp` (踢出设备)
- 同步：`GET /api/sync`
- 密码项：`POST /api/ciphers/create`、`PUT /api/ciphers/{id}`、`PUT /api/ciphers/{id}/delete`
- 文件夹：`POST /api/folders`、`PUT /api/folders/{id}`、`DELETE /api/folders/{id}`
- 2FA：`GET /api/two-factor`、`/api/two-factor/authenticator/*`
- 官方安卓设备探测：`GET /api/devices/knowndevice`
- icon支持: `GET /icons/{*res}`
- 域名规则支持: `GET /api/settings/domains`
- 加密密钥支持: `POST /api/accounts/kdf`
- 头像颜色支持: `POST /api/accounts/avatar`

## Vaultwarden 对齐新增接口

- `GET /api/collections`（当前返回空数组）
- `GET /api/policies`（当前返回空数组）
- `GET /api/organizations`（当前返回空数组）

## 🔐安全增强
- 登录校验，防止失效tocken成功登录

## 🔔 消息通知

本项目支持通过企业微信群机器人推送关键事件通知。

### 1. 配置 Webhook
在 Cloudflare 后台或通过 wrangler 设置密钥 `WEWORK_WEBHOOK_URL`：
```bash
wrangler secret put WEWORK_WEBHOOK_URL
# 输入形如 https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxxxxx 的地址
```

### 2. 配置通知开关
在 `wrangler.jsonc` 的 `vars` 中修改 `NOTIFY_EVENTS` 环境变量来控制发送哪些通知。

- **开启所有**：`"NOTIFY_EVENTS": "all"`
- **关闭所有**：`"NOTIFY_EVENTS": "none"`
- **按需开启**：逗号分隔，例如 `"NOTIFY_EVENTS": "login,login_failed,cipher_delete"`

**支持的事件列表：**
- `login`：登录成功
- `login_failed`：登录失败（密码错误、用户不存在、2FA 错误）
- `password`：修改主密码
- `email`：修改邮箱
- `kdf`：修改 KDF 设置
- `cipher_create`：新增密码项
- `cipher_update`：修改密码项
- `cipher_delete`：删除密码项（含软删除/恢复/彻底删除）
- `import`：导入数据
- `send_create` / `send_delete`：Send 创建与删除
- `2fa_enable` / `2fa_disable`：两步验证变更

**特性：**
- **GeoIP**：自动识别并显示操作 IP 的归属地（国家/地区/城市）。
- **美化模版**：使用 Markdown 格式，支持 Emoji 与关键信息高亮。
- **时区**：时间自动转换为 UTC+8（北京时间）。

## 许可证

MIT
