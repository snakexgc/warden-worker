# Vaultwarden 最近 45 次更新的逻辑合入记录

- 来源：`D:\gitrepo\vaultwarden` 当前 HEAD `17b159be`。
- 审阅范围：`1f99d9d2..17b159be`，共 45 次提交（架构师已完成逐提交分析，本轮按合入方案执行）。
- 目标：`D:\gitrepo\warden-worker`，开始时 HEAD 为 `e5d443b`，工作树干净。
- 处理原则：按个人单用户 Workers/D1/R2/DO 架构移植后端行为；前端与动态 CSS 更新由用户手动处理；本轮无任何数据库迁移。

## 逐提交结论

### 合入-适配（14 项）

| 提交 | 上游更新 | 本仓库处理 |
| --- | --- | --- |
| `28649978` + `863395f5` + `b723afe0` | `/api/config` 增加 `fillAssistRules` 与客户端功能开关机制 | 已合入：environment 增加 `fillAssistRules`（env `FILL_ASSIST_RULES_URL`，默认 `https://fillassist.bitwarden.com`，非法值回退默认并 warn）；featureStates 保留现有默认集合并新增 env `CLIENT_FEATURE_FLAGS`（逗号分隔 `name` 或 `name=bool`，未知 flag 丢弃并 warn，默认不开启新 flag）。 |
| `6ed6921c` | 日志转义用户输入 | 已合入：prelogin 两条日志、send/verify/recover/send-email-login 中插值邮箱的日志全部改为 `escape_debug()`。 |
| `acb574b7` | Send file data 校验 + send-email-login 的 auth request 收紧 | 已合入：Send file v2 的 data 非对象返回 400 `"Invalid Send file data"`；auth request 分支增加 `approved`/`creation_date` 校验，未批准、已消费、超 5 分钟（RFC3339 解析失败按过期）或 device/IP/access code 不匹配统一返回 401 `"AuthRequest doesn't exist"`。 |
| `e056359a` | 删除用户时广播登出 | 已合入：`cascade_delete_user_data` 在 `DELETE FROM users` 前发布 `UpdateType::LogOut` 用户通知，失败仅 warn 不阻断删除。 |
| `0dbc92f2` | 2FA remember 时长可配置 | 已合入：`generate_2fa_remember_claims` 增加 `days` 参数；登录流程经 `TWO_FACTOR_REMEMBER_DAYS` env 读取（默认 30，clamp 1..=90，解析失败回退默认）。README 已文档化。 |
| `df2cd3c8` | `biometrics-sdk-ipc` flag | 已合入 `CLIENT_FEATURE_FLAGS` 支持列表。 |
| `0e93d15b` | Windows autotype flags | 已合入 `windows-desktop-autotype`、`windows-desktop-autotype-ga` 至支持列表。 |
| `64ae55ce` | 附件通知时机 + 导入忽略 organizationId | 已合入：`create_attachment_v2` 在 INSERT 后即 bump revision 并发布 SyncCipherUpdate；`upload_attachment_v2` 移除二次通知（保留 size/cipher.updated_at 更新）；v1 legacy multipart 路径不动。`import_data` 开头将所有 cipher 的 `organization_id` 置 None（上游 PR #7906）。 |
| `b71cb7a8`（片段） | OTP 计数 off-by-one | 已合入：`validate_protected_action_otp` 改为先判 `attempts >= LIMIT`（不增计数）→ 过期判断 → 不匹配才计数并报错；提取纯函数 `evaluate_protected_action_otp` 并补单测（LIMIT=3 恰好允许 3 次错误，第 3 次输入正确码仍成功）。 |
| `42aa3ee1` | WS 半开连接关闭 | 已合入：NOTIFICATIONS_HUB DO 接受连接后 `serialize_attachment(LastReceived::now())`；任何入站消息刷新时间戳；alarm 每 15s 检查，无记录或超 30s 未收到消息即 `close(1000, "client timeout")`，否则照发 SIGNALR ping。`websocket_close` 清 alarm 逻辑不动。 |
| `895ec2b1`（部分） | GET /api/accounts/keys + prelogin 稳定 KDF + 附件 TTL | 已合入：新增 `GET /api/accounts/keys`（private/public key 为空串时 404 `"User has no key pair"`，SDK 以 404 判定无密钥对；响应含 `key`/`publicKey`/`privateKey`/`accountKeys`/`object:"keys"`，accountKeys 抽为共享函数供 profile/sync 复用）；prelogin 未知邮箱按 `HMAC-SHA256(access_secret, 规范化 email)` 首 8 字节 u64 对 6 取模，从 `[(默认)×2, (PBKDF2,100_000), (PBKDF2,5_000), (Argon2id,3,64,4), (Argon2id,6,32,4)]` 稳定选择；附件下载链接 TTL 5→1 分钟。 |
| `acbf4901` | 2FA userVerificationToken | 已合入，详见下节。 |

### 跳过（企业功能，单用户模型不适用）

`904b8011` Custom Roles、`79ee29d5` 审计事件、`be5d3ad9` bulk member/SSO、`e5a90968` bulk share、`7ce705be` 组 manage flag、`c925c04d` sync org key、`b8089e31` 组织账户恢复、`8647af8f` 紧急访问、`c687cacb` 组导入、`d1cbd027` 组织策略 revisionDate、`a2efadc6` SSO 登录、`415df400` Duo/SSO purge。

### 跳过（栈不适用）

`17b159be` OpenDAL（本仓库 R2 原生绑定）、`44c4853d` Rocket 升级（WS ping 修正本仓库已有）、`7c188967`/`f4696877`/`5d870b79` crate/构建链、`58a980f8` riscv64、`e2d63cfc` icon cookie jar、`80d18594` push relay、`82fc47e8` 请求级日志。

### 跳过（纯文档/typo）

`0f44744e`、`de6d2066`、`8b569260`、`29659900`、`970cc491`。

### 已满足（无需改动，补测试固化）

- `f1c7eccd`（批量 move 单次 revision）：本仓库本来就是修复后行为。
- `64895524`（FK 级联）：schema 已有 `ON DELETE CASCADE`；本轮新增 SQLite 回归测试固化（删用户后 devices/auth_requests 为空）。
- `a96912bf`（95MiB 上限）：已有，无配额机制。

### 流程不适用

`42660af7`（注册邮件链接点击流）：本仓库注册走 `/identity/accounts/register/finish` + 验证令牌，无邮件链接点击流；若用户升级前端后注册流调用 `POST /identity/accounts/register/verification-email-clicked`（该端点本仓库已存在）再评估是否需要补等价行为。

## 2FA userVerificationToken 机制（`acbf4901`）实现说明

新文件 `src/two_factor_verification.rs`：

- `TwoFactorVerificationClaims<T> { nbf, exp, iss: "warden-worker|2fa-verify", sub, enabled, claims }`，exp = now + 300s，签名复用 `jwt::encode_hs256/decode_hs256` 与 `state.jwt_keys.access_secret`；
- `AuthenticatorClaims { authenticator_key }`、`EmailClaims { email }`、`WebauthnClaims { webauthn_keys: Vec<i32> }` 全部 `deny_unknown_fields`，跨 provider 复用 token 会因反序列化失败被拒绝（单测覆盖）；
- validate 校验 iss、sub==当前用户、enabled 状态匹配、claims 与当前值匹配（Authenticator: TOTP key；Email: mfa email（仅 enabled=true 时比较）；WebAuthn: 凭证 slot id 列表），错误统一 `AppError::Unauthorized("Invalid verification token: ...")` 语义对齐上游。

端点变化（`src/handlers/two_factor.rs` + `src/handlers/webauthn.rs`），请求侧一律双路径（`userVerificationToken` 优先，`masterPasswordHash`/`otp` 密码回退，兼容老客户端）：

- `get_authenticator`：响应新增 `authenticator: {enabled, key}` 与 `userVerificationToken`，**同时保留旧平铺 `enabled`/`key`/`object` 字段**（无键名冲突，旧前端可用）。
- `activate_authenticator`（POST/PUT `/api/two-factor/authenticator`）：请求体可选 `userVerificationToken`，按 enabled=false + key 匹配校验；响应新增嵌套 `authenticator` 对象并保留旧平铺字段。
- `disable_authenticator`（DELETE）：请求体可选 `key + userVerificationToken`（token 按 enabled=true + key 校验），保留密码路径；`masterPasswordHash` 与 `type` 均改为可选。
- `get_email`：**`email` 键存在新旧形状冲突（旧为字符串、新为对象），按上游新形状为准**：`{"email": {"enabled":..,"email":..}, "userVerificationToken":..}`（额外保留顶层 `enabled`/`object`，无冲突）。
- `send_email`（POST `/api/two-factor/send-email`）：增加 token 鉴权路径（enabled=false，email 不比较，对齐上游）。
- `verify_email`（PUT `/api/two-factor/email`）：`EmailData` 增加 `userVerificationToken`（enabled=false 校验）。
- `disable_email`（DELETE）：token 路径按库中当前 email + enabled=true 校验；无 email 2FA 记录时跳过校验（对齐上游）。
- `get_webauthn` / `POST/PUT/DELETE /api/two-factor/webauthn` / `get-webauthn-challenge`：同模式，claims 为凭证 slot id 列表；`get_webauthn` 响应新增 `webAuthn: {enabled, keys}` 嵌套对象与 `userVerificationToken`，put/delete 响应同样附带嵌套 `webAuthn`，全部保留旧平铺字段。
- **保留** `PUT /api/two-factor/disable`（上游已删，但本仓库 README 已承诺、老客户端在用）。
- 所有 disable 路径（含新增 token 路径）继续调用 `two_factor::clear_remember_tokens`。
- 登录 token grant 的 `twoFactorToken` 机制不变。

**响应形状兼容策略落实**：当前 web-vault 为 v2026.7.0（旧形状最后一版），用户将手动升级前端。无键名冲突的端点（authenticator、webauthn）同时输出新旧字段；有冲突的 email 端点按新形状输出。**注意：部署后、前端升级前，web 端 Email 2FA 设置卡片可能显示异常（`email` 字段由字符串变为对象），登录流不受影响。**

## 后端行为变化汇总

### 账户与认证

- 新增 `GET /api/accounts/keys`：返回用户密钥对（含 `accountKeys`），无密钥对时 404（SDK 判定语义）。
- prelogin 未知邮箱返回按键控哈希稳定选择的 KDF 参数，防枚举指纹；已知用户分支不变。
- 删除用户（含 delete-recover-token 路径）在删除前广播 LogOut 通知。
- 2FA remember 时长可配置（`TWO_FACTOR_REMEMBER_DAYS`，1..=90，默认 30）。
- protected-action OTP 计数修复：limit 判定不再先增计数，第 3 次尝试输入正确码可成功。

### 附件与导入

- 附件下载 URL TTL 由 5 分钟降为 1 分钟。
- 附件 v2 创建即通知（SyncCipherUpdate + revision bump），上传完成不再二次通知。
- 导入忽略 organizationId，组织导出的数据可导入个人密码库（落库 organization_id 为 NULL）。

### /api/config

- environment 增加 `fillAssistRules`（`FILL_ASSIST_RULES_URL`）。
- featureStates 支持 `CLIENT_FEATURE_FLAGS` 追加/覆盖（默认不开启新 flag）。

### 通知（NOTIFICATIONS_HUB DO）

- WebSocket 半开连接检测：30 秒无入站消息即主动 close(1000, "client timeout")。

### Send

- file v2 的 data 非对象返回 400。
- send-email-login 的 auth request 须已批准、未消费、5 分钟内且 device/IP/access code 匹配。

## 用户需要手动处理的前端变化

1. **web-vault 升级 v2026.7.0 → v2026.10.1**（对应上游 `1f802f8e` + `5d870b79` 的 Web Vault 构建更新）。**前置条件：先部署本轮后端**——新 web-vault 的 2FA 设置页依赖 `userVerificationToken` 流（密码回退路径也保留，但建议后端先行）。升级后 Email 2FA 卡片恢复正常（读取新的 `email` 对象形状）。
2. 延续上轮 `f9f011d5`、`1f99d9d2` 的 CSS 适配建议不变（`src/handlers/css.rs` 及其配置）。

本轮未修改 `static/**`、`src/handlers/css.rs`、`sql/schema.sql` 与 `sql/migrations/**`；dry-run 触发的 Turnstile 补丁已还原，前端零差异。

## 验证

- `cargo test --all-targets --locked`：94 passed（新增 17：跨 provider token 拒绝、token 往返/过期、email/webauthn claims 匹配、OTP 计数边界 3 项、auth request 过期 3 项、prelogin 稳定 KDF 2 项等）。
- `node --test tests/*.test.mjs`：31 passed（新增 `tests/upstream_sync_2026_11.test.mjs` 6 项：FK 级联、导入 orgId 置空及落库 NULL、GET /api/accounts/keys 路由注册与 404 语义、附件 TTL=1、Send data 非对象 400、删用户先广播登出）。
- `cargo clippy --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check` 与 `git diff --check`：通过。
- `worker-build --release`：通过，生成 Wasm/JS 发布产物（最终代码重新构建验证，wasm 时间戳晚于最后一次源码修改）。
- `wrangler deploy --dry-run`：通过一次完整验证（识别 D1、R2、两个 DO、三个限流器及静态资源，custom build 全链路执行成功）；dry-run 构建命令触发的 Turnstile HTML 补丁已用 `git checkout` 还原，`git status` 确认 `static/**` 零差异。
  - 环境备注：本任务执行环境的沙箱（sandbox-center/WorkBuddy 文件守护）会在 `build/.gitignore`（wasm-pack 生成的 1 字节文件，仓库 git 已忽略）上持有句柄并拒绝删除/重命名，导致后续重复 dry-run 内嵌的 worker-build 报 "Failed to move .gitignore from staging to output (os error 5)"。删除该文件后重跑即可通过（首轮即如此）。此为执行环境限制而非代码问题；wrangler.jsonc 未改动，dry-run 的配置验证结论不受影响。
- 未执行真实 Bitwarden 客户端或浏览器端到端验证；未提交、推送或部署。

变更全部保留在当前工作区。
