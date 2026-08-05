# Warden Worker × Vaultwarden 文件级详细对比报告（2026-08-05）

## 对比基准与方法

| 项 | 值 |
| --- | --- |
| 目标仓库（参考/上游，只读） | `D:\gitrepo\vaultwarden` @ `2629bcbe1380c894e3a7f52cafcac3988edb8fbb`（Rocket / SQLite·MySQL·PostgreSQL / reqwest / SMTP / 本地存储） |
| 当前仓库 | `D:\gitrepo\warden-worker` @ `0b54345aaeff0a8c6164e869fa7af41cba355286`（Axum / wasm32 / D1 / R2 / Durable Objects / fetch / Web 通知扩展） |
| 方法 | 全量 src 文件 MD5 哈希比对 + 分组逐文件 `git diff --no-index` 精读（四个并行分组：api/core、two_factor、db、api 杂项+根配置） |
| 范围 | 优先 src 目录；兼顾根目录关键配置文件（Cargo.toml、wrangler.jsonc 等） |

**重要前提**：当前仓库是 Vaultwarden 的 Cloudflare Workers **重写实现**，并非拷贝，因此"完全一致"是稀有状态。本报告将每个文件的差异分为三类：

- **可接受差异**：为实现 Cloudflare Workers 兼容性而进行的必要特殊处理（框架装配、D1/R2/DO、fetch、通知通道、子模块拆分、配置来源等）。
- **不可接受差异**：非兼容性原因导致的功能逻辑/实现方式差异（鉴权、校验、响应、状态码、数据语义、安全约束等可观察行为差异）。
- **特有功能**：当前仓库特意保留/新增的能力，相关文件与代码块**必须保护，不得误判为待修改差异点**。

---

## 一、文件结构对比

### 1.1 src 目录结构总览

```text
Vaultwarden src/                               Warden Worker src/
  api/                                            api/
    core/                                          core/
      two_factor/{8 文件}                           two_factor/{8 文件}  —— 同名同层级 ✓
      accounts.rs                                   accounts.rs
      ciphers.rs                                    ciphers.rs
      emergency_access.rs  folders.rs  events.rs     emergency_access.rs folders.rs events.rs  ✓
      mod.rs                                        mod.rs
      organizations.rs  public.rs  sends.rs          organizations.rs public.rs sends.rs        ✓
    admin.rs                                      + accounts/devices.rs（拆分）
    icons.rs  identity.rs  notifications.rs         ciphers/attachments.rs、ciphers/sync.rs、
    push.rs  web.rs                                 ciphers/sync/models.rs（拆分）
    mod.rs                                        + imports.rs、imports/models.rs（导入 DTO）
                                                  + meta/{config,hibp,mod,settings}.rs（拆分）
                                                  icons.rs identity.rs notifications.rs push.rs web.rs mod.rs
  auth/send.rs                                    （sends 逻辑在 api/core/sends.rs）
  auth.rs  config.rs  crypto.rs  error.rs         auth.rs crypto.rs error.rs
  http_client.rs  mail.rs  main.rs                + crypto/password.rs（服务端密码验证适配）
  ratelimit.rs  sso.rs  sso_client.rs             + lib.rs（Worker 入口）
  storage.rs  util.rs                             + entry.js、heavy_do_routing.mjs（Wrangler JS 入口）
  db/                                              db/
    mod.rs   query_logger.rs   schema.rs            mod.rs（D1 简化版）
    models/{20 文件，含 sso_auth.rs}                models/{19 文件，无 sso_auth.rs}
  static/**（admin 模板/脚本、email hbs、图片）      （静态资源移至根目录 static/web-vault，由 Cloudflare Assets 接管）
```

### 1.2 同名同层级文件（内容逐一比对，见第三节）

共 **45 对** 同名文件：api/core 9 个、api/core/two_factor 8 个、api 6 个、根级 3 个（auth.rs/crypto.rs/error.rs）、db 层 20 个。其中仅 `db/models/emergency_access.rs` 达到**完全一致**（字段/常量/序列化逐一对齐），其余 44 对均存在差异（绝大多数为可接受的兼容性差异）。

### 1.3 仅存在于当前仓库（特有功能，保护）

| 目录/文件 | 职责 |
| --- | --- |
| `src/lib.rs` | Worker fetch 入口：D1/JWT 密钥/2FA 密钥初始化、CORS、notifications DO 代理、Axum 服务 |
| `src/entry.js`、`src/heavy_do_routing.mjs` | Wrangler JS 入口、HeavyDo 卸载路径表、固定长度流 |
| `src/worker_runtime/**`（11 个文件） | Axum 路由全表、Durable Object 广播、R2 分片存储、边缘 JWT、D1 密钥管理、后台任务、HeavyDo、等效域名、边缘 WebAuthn/Passkey |
| `src/extensions/**`（notify 10 文件 + usage.rs） | Webhook/Telegram/企业微信通知（通道/模板/outbox）、D1/R2 用量端点 |
| `src/crypto/password.rs` | 服务端密码验证适配（PBKDF2 600k 迭代、自动升级） |
| `src/api/core/accounts/devices.rs` | 设备与 AuthRequest 端点（自 VW accounts.rs 拆出） |
| `src/api/core/ciphers/{attachments,sync,sync/models}.rs` | 附件/R2 上传下载、sync 响应 DTO（自 VW ciphers.rs 拆出） |
| `src/api/core/imports.rs`、`imports/models.rs` | 个人/组织导入（共享 D1 批量 SQL） |
| `src/api/core/meta/**` | config/alive/now/version/HIBP/等效域名端点（自 VW api/core/mod.rs 拆出） |
| `static/`（web-vault/**、demo.html、send-verify.html） | Cloudflare Assets 静态资源 |

### 1.4 仅存在于目标仓库（及当前仓库等价物）

| Vaultwarden 文件 | 当前仓库等价物 | 结论 |
| --- | --- | --- |
| `api/admin.rs` | 无 | **未实现**（无 /admin 界面与 API） |
| `auth/send.rs` | `api/core/sends.rs` 的 `issue_send_access_token` | 有等价 |
| `config.rs` | `api/core/meta/config.rs` + wrangler.jsonc vars + D1 密钥表 | 有等价 |
| `http_client.rs` | `worker::Fetch`（各文件直接 fetch） | 有等价（无 SSRF host 校验基础设施，见 icons.rs） |
| `mail.rs` | `extensions/notify/**` | 有等价（通道不同：SMTP→Webhook/Telegram/企业微信） |
| `main.rs` | `lib.rs` + `entry.js` | 有等价（无 CLI/argon2 hash 命令） |
| `ratelimit.rs` | Cloudflare Rate Limiting 绑定（wrangler.jsonc） | 有等价 |
| `sso.rs`、`sso_client.rs` | 无（占位：`SSO_PLACEHOLDER_ORG_ID`、`get_org_domain_sso_verified`、`"sso": null`） | **未实现**（明确占位，不宣称支持） |
| `storage.rs` | `worker_runtime/r2_file.rs`（95MiB 上限、8MiB 分片） | 有等价 |
| `util.rs` | 分散实现（format_date→meta、ClientIp→auth.rs） | 有等价 |
| `db/schema.rs` | `sql/schema.sql`（118 语句、38 表、41 索引） | 有等价 |
| `db/query_logger.rs` | 无（D1 无 SQL instrumentation；logging.rs 只做请求日志） | 无等价，影响低 |
| `db/models/sso_auth.rs` | 无（SSO 未实现） | 无等价 |
| `static/**` | admin 模板/脚本无等价；email 模板→notify/templates；图片→static/web-vault/images | 部分等价 |

---

## 二、特有功能保护清单（不得误判为差异点）

以下功能与代码块属当前仓库特有，对比时**一律按"保护，勿改"处理**：

1. **Passkey/密钥登录全套**：`/api/webauthn/*`（list/create/update/delete、attestation/assertion-options、prf-probe）、`/identity/accounts/webauthn/assertion-options` 无密码登录；PRF 加密密钥状态机；`worker_runtime/webauthn.rs` 中 challenge 一次性消费、sign counter 回放防护、ES256/RS256 验证。Vaultwarden 当前基线明确不支持 passkey login（`GET /api/webauthn` 返回空列表）。
2. **Turnstile 人机验证**：`/send-verify` + `/api/send-verify` + 签名 cookie 通行证（sends.rs）；未配置 key 时自动跳过，不影响正常访问。
3. **Webhook/Telegram/企业微信通知**：`extensions/notify/**`（通道、模板、outbox），替代 SMTP 邮件通道；注册验证、组织/紧急访问邀请、受保护操作发码、未完成 2FA 告警等均由此投递。
4. **Durable Object 实时广播**：`worker_runtime/router.rs` 的 NotificationsHub（tag 广播、x-internal-notify 内部鉴权、手写 MessagePack、SignalR 帧与 VW wire 协议一致）。
5. **D1/R2/HeavyDo 基础设施**：D1 batch 原子 SQL、`DELETE ... RETURNING` 一次性消费（Duo OIDC state/nonce、webauthn challenge 防回放）、R2 分片上传/固定长度流、HeavyDo CPU 卸载、`worker_runtime/two_factor_key_manager.rs`（AES-GCM 加密 2FA secret，密钥存 D1）。
6. **Send 访问 OAuth 风格 access token**（`issue_send_access_token`，响应 `{access_token,expires_in,token_type,scope:"api.send.access"}`），与 Bitwarden 官方新版 Send 访问流程一致。
7. **兼容别名路由与扩展端点**：`/two-factor/recover`、`DELETE /api/two-factor/email`、`/api/accounts/request-otp|verify-otp` 双前缀、`/api/d1/usage`、`/.well-known/apple-app-site-association`、HEAD 等。
8. **安全加固项**：auth-request access code / Send 密码哈希存储、2FA 尝试计数与过期校验、Duo host 白名单、YUBICO_SERVER 强制 https、`ua_history`/`email_new_token_sent_at` 列、`users_organizations.permissions` 持久化（VW 为 TODO 硬编码）。
9. **子模块拆分**：accounts/devices.rs、ciphers/{attachments,sync,sync/models}.rs、meta/*、imports.rs —— 公开职责仍由同名主模块统一暴露，拆分后职责等价。

---

## 三、文件内容对比（按目录层级）

### 3.1 src/api/core

#### api/core/accounts.rs（含 accounts/devices.rs 拆分）
- **状态：存在不可接受差异**（拆分职责等价 ✓，devices/auth-request 端点齐全）
- 可接受差异：每端点显式 `verify_security_stamp` ≡ VW Headers 全局校验；注册验证/通知走 JWT 自签 + Webhook 通道；prelogin kdfSettings 一致；`providers`/`providerOrganizations` 固定 `[]`（不实现 Provider）。
- 不可接受差异及建议：
  1. **P1 `SIGNUPS_VERIFY` 默认值背离**：[accounts.rs:607](file:///d:/gitrepo/warden-worker/src/api/core/accounts.rs#L607) 默认 `true`，VW [config.rs:621](file:///D:/gitrepo/vaultwarden/src/config.rs#L621) 默认 `false`；未配置邮箱通道时普通注册默认被拒。建议：默认改 `false`，或拆分 register/register-finish 两条路由。
  2. **P2 删除恢复邮件缺失**：`post_delete_recover` 仅记日志返回 `{}`，VW 发送含删除链接的邮件，用户无法恢复删除。建议：补 action link 投递。
  3. **P2 旋转账户密钥拒绝紧急访问/组织恢复数据**：`rotate_user_account_keys` 对非空列表直接 400，VW 会同步更新 emergency access key 与 `reset_password_key`。建议：增加对应更新分支。
  4. **P2/P3 stamp_exception 机制缺失**：VW 改密后 2 分钟内允许旧 stamp 访问 rotatekey/revision-date 等路由；建议用 D1 临时例外记录实现。
  5. **P3 `verify_password` 响应恒为硬编码空 `masterPasswordPolicy`**：建议接入组织策略查询。
  6. **P3 状态码**：not found/校验失败 404/401 vs VW 默认 400。
  7. **P3 事件日志缺失**：注册/登录/改密处 VW 写 `log_user_event`。

#### api/core/ciphers.rs（含 ciphers/attachments.rs、sync.rs、sync/models.rs 拆分）
- **状态：存在不可接受差异**（拆分职责等价 ✓）
- 可接受差异：组织权限矩阵用单条授权感知 SQL（含 groups/collections/manage/hide_passwords 分支）；SSH key 版本过滤、lastKnownRevisionDate 陈旧检查、collections_v2、集合对称差集更新均与 VW 对齐；附件走 R2。
- 不可接受差异及建议：
  1. **P1 `/api/ciphers/purge` 忽略 organization 参数**：[ciphers.rs:243](file:///d:/gitrepo/warden-worker/src/api/core/ciphers.rs#L243) `purge_personal_vault` 恒删当前用户个人库。VW 有 Owner 权限的 `purge_org_vault`（清空组织保险库）；Web vault 组织管理员操作会**误删个人保险库**。建议：解析 `organization` 查询参数并拒绝/改走 Owner 版实现。
  2. **P2 服务端事件日志缺失**：软删/恢复/归档等 VW 写 `log_event`。
  3. **P3 批量上限更严**：move ≤40、share ≤40、bulk-collections ≤80，VW 无限制。
  4. **P3 `update_cipher` 拒绝个人→组织转移**（share 端点可替代）。
  5. **P3 回收站自动清理 cron 缺失**；软删/恢复返回 cipher JSON 而非空体；get_org_ciphers 权限严格度（confirmed vs ManagerHeadersLoose）。

#### api/core/emergency_access.rs
- **状态：存在不可接受差异（轻微）**
- 可接受差异：邀请 JWT 自签自验 + action link 通道；18 个端点与状态机与 VW 一一对应；access type 数字/字符串双解析；服务端 PBKDF2 语义一致。
- 不可接受差异（均 P3）：注册时接受紧急访问邀请流程缺失；`emergency_notification_reminder_job` 提醒 cron 缺失（仅有自动 approve）；grantee 用户缺失时 404 vs VW 跳过该条；无效 token 401 vs 400。

#### api/core/events.rs
- **状态：存在不可接受差异**
- 可接受差异：`post_events_collect` 分类处理（1000-1099/1600-1699/其余）与 VW 对应；分页 30 条与 continuation token 语义一致；事件禁用返回 200 空列表。
- 不可接受差异及建议：
  1. **P2 `get_cipher_events` 无权限返回 404/403**，VW 返回 200 空列表。建议改空列表。
  2. **P2 成员事件查询语义不同**：VW 匹配 `user_uuid` **或** `act_user_uuid`；当前只按 `membership_id`，且服务端组织事件从未写入（VW 有 20+ 处 `log_event`/`log_user_event`）。建议：补服务端事件写入；member events 改按 user 关联。
  3. **P3 40 条上限、分页 `<` vs `<=`、成员不存在 404 vs 空列表**。

#### api/core/folders.rs
- **状态：存在不可接受差异（轻微）**
- 可接受差异：路由集合与响应字段（id/revisionDate/name/object）与 VW 一致；创建/更新/删除均 revision + 实时通知。
- 不可接受差异：**P3 文件夹不存在返回 404**，VW `err!("Invalid folder")` 默认 400。建议统一为 400。

#### api/core/mod.rs（拆至 meta/{config,hibp,settings}.rs）
- **状态：存在不可接受差异（轻微）**
- 可接受差异：HIBP fetch + 无 key 分支与 VW 一致；config 输出（version/featureStates/push/communication）基本一致；alive 做 D1 探活；拆分职责等价 ✓。
- 不可接受差异：**P3 404 兜底缺失**——VW `api_not_found` catcher 返回标准 JSON 错误，Axum 默认纯文本 404。建议在 router.rs 注册 fallback。

#### api/core/organizations.rs
- **状态：存在不可接受差异**
- 可接受差异：路由集合与 VW 一一对应（organizations/collections/groups/policies/members/billing/plans/export/keys/domain-sso）；`require_admin`≡AdminHeaders、`require_owner`≡OwnerHeaders；create_organization 建 org+Owner+默认 collection 与 VW 等价。
- 不可接受差异及建议：
  1. **P2 事件审计完全缺失**：VW organizations.rs 有 22 处 `log_event`，当前全文件 0 处。建议按 VW 事件点补齐。
  2. **P2 `require_collection_manager` 额外要求 Manager `access_all != 0`**：[organizations.rs:504](file:///d:/gitrepo/warden-worker/src/api/core/organizations.rs#L504)，VW `ManagerHeadersLoose` 仅要求 confirmed + type≥Manager。access_all=0 的 Manager 无法访问集合管理端点。建议对齐。
  3. **P3 批量上限更严、domain-sso verified 占位响应**。

#### api/core/public.rs
- **状态：存在可接受差异（无不可接受项）**
- API token 校验（iss/scope/client_id/sub 匹配 org_api_key）≡ VW PublicToken；deleted 撤销/restore/overwrite_existing/最后 owner 保护/组导入均等价；2000 条上限与 externalId 唯一性为更严方向。

#### api/core/sends.rs
- **状态：存在可接受差异（无不可接受项）**
- 路由集合与 VW 完全等价（legacy/v2/download?t=）；下载 token JWT 自签 `sub="{send_id}/{file_id}"` 与 VW 等价；Send 密码 PBKDF2-HMAC-SHA256 等价；访问计数/最大次数/≤31 天删除/隐藏邮箱策略一致。
- **特有功能（保护）**：Turnstile 人机验证 + `/send-verify`；Send 访问 OAuth 风格 access token。

### 3.2 src/api/core/two_factor

#### two_factor/authenticator.rs
- **状态：存在不可接受差异**
- 特有功能（保护）：`authenticator_request/enable/disable` 自定义开通流；TOTP secret AES-256-GCM 加密存 D1。
- 可接受差异：`get_authenticator`/`activate_authenticator` 响应体、base32+20 字节校验、±1 步窗口、recovery code 语义与 VW 等价；登录 TOTP 走 `consume_totp_code` last_used 原子回放防护。
- 不可接受差异及建议：
  1. **P2 `PasswordOrOtpData::validate` 硬编码 `delete_if_valid=true`**（见 mod.rs L37-58）：VW 在 `generate_authenticator` 用 `false`、仅 activate 用 `true`；导致"get→activate 同 OTP"上游流程第二步失败。建议恢复 `delete_if_valid` 参数。
  2. **P3 密码错误返回 401** vs VW 400。

#### two_factor/duo.rs
- **状态：存在可接受差异**
- 可接受差异：get/activate 三态响应体、`duo_api_check`、sign/parse/validate 签名校验逻辑与 VW 等价；`valid_host` 防 URL 注入、`DUO_AKEY` 配置模型为加固/平台适配。
- 不可接受差异（均 P3，可不改）：全局凭据缺失提前 400（VW 登录时才失败）；`validate_duo_login` 失败 401 vs 400。

#### two_factor/duo_oidc.rs
- **状态：存在可接受差异**
- 特有功能（保护）：D1 `TwoFactorDuoContext::take`（DELETE...RETURNING 原子消费 state/nonce 防回放）；purge 走 lib.rs Cron；fetch 调用 Duo OAuth。
- 可接受差异：STATE_LENGTH、nonce+device 绑定、JWT HS512、300s 有效期、aud/iss、required claims 与 VW 全对齐。
- 不可接受差异（均 P3，可不改）：`post_form` 接受 2xx vs VW 仅 200；失败路径 401 vs 400。

#### two_factor/email.rs
- **状态：存在不可接受差异（轻微）**
- 特有功能（保护）：发码走 Webhook 通知通道（非 SMTP）；Auth Request 兼容（auth_request_id/access_code + SHA256 比对）；`issue_email_login_token` 复用。
- 可接受差异：send/get/verify 流程（challenge 1002→转正 1）等价；登录校验常量时间比对 + 尝试计数（≥3 重置）等价；`disable_email` 为 Bitwarden server 标准端点。
- 不可接受差异：**P3 `verify_email` 响应 `"enabled": true` 布尔 vs VW 字符串 `"true"`**（可保留，更符合新客户端契约）。

#### two_factor/mod.rs
- **状态：存在不可接受差异**
- 特有功能（保护）：`/two-factor/recover`（Bitwarden server 端点，VW 未实现）；`process_incomplete_notifications` 超时告警投递 Webhook/Telegram/企业微信。
- 可接受差异：`two_factor_status`/`get_recover`/`disable_twofactor`/`get_device_verification_settings` 响应体与 VW 一致。
- 不可接受差异及建议：
  1. **P2 `disable_twofactor` 缺失 `enforce_2fa_policy`**：VW 删除最后一个 2FA 后吊销"开启 2FA 组织策略"组织中的非管理员成员；当前全仓库无 `TwoFactorAuthentication` 策略处理（组织策略体系未实现）。建议在组织策略模块统一实现后接入禁用流程。
  2. **P2 `get_recover` 的 `delete_if_valid` 同源问题**（见 authenticator.rs）。

#### two_factor/protected_actions.rs
- **状态：存在可接受差异（无不可接受项）**
- 30 秒冷却、3 次尝试上限、600 秒过期、常量时间比对与 VW 一致（尝试超限直接删除为更严格方向）；错误文案逐字一致；路由覆盖 `/accounts/*` 与 `/api/accounts/*`。

#### two_factor/webauthn.rs
- **状态：存在不可接受差异（轻微）**
- 特有功能（保护）：Passkey/密钥登录全套端点与 PRF 状态机；协议实现在 worker_runtime/webauthn.rs（challenge 一次性消费、sign counter 单调性、ES256/RS256、origin/rpId 校验）。
- 可接受差异：四个 2FA 端点路径与响应体对齐（含 twoFactorWebAuthn/twoFactorU2f 怪癖命名）；slot 1..5、excludeCredentials、userVerification preferred（更严）保留；无 U2F 历史迁移（当前无历史数据）。
- 不可接受差异：**P3 `get_webauthn_challenge` 响应缺 `"status":"ok"`/`"errorMessage":""` 顶层字段**（可补充以求逐字兼容）。

#### two_factor/yubikey.rs
- **状态：存在不可接受差异（轻微）**
- 可接受差异：Yubico WSAPI 2.0 fetch 自研实现（id/nonce/otp/timestamp + HMAC-SHA1 签名、常量时间、回显校验）与 yubico crate 同等强度；get/activate/validate 流程一致；`YUBICO_SECRET_KEY` base64 解码等价；强制 https 为加固。
- 不可接受差异（均 P3，可保留）：空 keys 激活时删除既有记录（VW 仅返回 enabled:false）；public id 去重（VW 保留重复）；失败 401 vs 400。

### 3.3 src/api

#### api/icons.rs
- **状态：存在不可接受差异**
- 差异：[icons.rs:17-19](file:///d:/gitrepo/warden-worker/src/api/icons.rs#L17-L19) 直接代理 `vault.bitwarden.com`，固定 `max-age=604800`。VW 有 `get_valid_host`/`should_block_host` 域名与 IP 校验、正/负缓存区分、fallback-icon、图标类型嗅探。建议（P2）：至少补域名格式/黑名单校验与合理缓存策略。

#### api/identity.rs
- **状态：存在不可接受差异**
- 特有功能（保护）：`grant_type="webauthn"` passkey 登录、`bw_access_token`/`bw_refresh_token` Cookie、登录事件 Webhook 通知、recovery code provider=8 分支、后台设备 upsert。
- 可接受差异：2FA 响应格式（TwoFactorProviders/TwoFactorProviders2/error=invalid_grant）与 VW 一致；send_access/client_credentials/password/refresh_token 分支齐全。
- 不可接受差异及建议：
  1. **P1 refresh token 机制不等价**：[identity.rs:2121-2264](file:///d:/gitrepo/warden-worker/src/api/identity.rs#L2121-L2264) refresh token 与 access token 同构（仅换 secret），只校验 stamp；VW 用独立 `RefreshJwtClaims{sub: AuthMethod, device_token, token}`，按设备查库、轮换 token、区分 AuthMethod。**已删除/登出的设备仍可续期 refresh 并"复活"**。建议：refresh 绑定 `devices.refresh_token`（schema.sql 中已有该列）并支持登出撤销。
  2. **P1 密码错误返回 401**（[identity.rs:1144](file:///d:/gitrepo/warden-worker/src/api/identity.rs#L1144)、[1298](file:///d:/gitrepo/warden-worker/src/api/identity.rs#L1298)），VW `err_silent!` 默认 400。
  3. **P2 登录成功响应 `"Key"` 恒返回**（VW 仅 akey 非空时返回）、`MasterPasswordPolicy` 恒 `{}`（VW 合并组织策略）。随组织策略实现补齐。

#### api/mod.rs
- **状态：存在可接受差异**
- VW 做 Rocket 装配、`MasterPasswordPolicy` 合并计算、公共校验、catchers/purge 任务导出；当前仓库仅导出模块与 AppState/api_router。**P1 缺口**：`master_password_policy()` 组织策略合并无对应实现（identity.rs 恒返回空对象）——属组织策略体系缺失，随组织功能一并补齐。

#### api/notifications.rs
- **状态：存在可接受差异（含随组织功能补齐项）**
- 特有功能（保护）：整个 NotificationsHub DO 实现（tag 广播、x-internal-notify、alarm 保活、手写 MessagePack）；wire 协议对齐（INITIAL_RESPONSE、SignalR 帧、ping、匿名目标拼写）。
- 差异：`UpdateType` 缺 `SyncOrgKeys=6`（VW 有；当前组织功能未启用，值未激活）。**P2** 随组织功能补齐。

#### api/push.rs
- **状态：存在可接受差异**
- Bitwarden Push Relay 客户端协议一致（client_credentials/scope=api.push/installation.{id} 取 token、/push/register/delete/send、payload 字段逐项对应）；半衰缓存等价；组织 cipher 不推送（两边一致）。
- 差异：**P3** `push_auth_event` 的 deviceId/identifier 恒 null（VW 传真实 acting device）——建议回填。

#### api/web.rs
- **状态：存在可接受差异**
- 特有功能（保护）：`vaultwarden_css` 动态 CSS 生成（运行时规则 + 用户 CSS，VW 为 SCSS 编译，功能等价）。
- 静态资源由 Cloudflare Assets 接管（SPA 404）；app-id.json/apple-app-site-association/alive/now/version 分别由 static 与 meta/ 承担。无不可接受差异。

### 3.4 根级文件

#### auth.rs
- **状态：存在不可接受差异（token 契约）**
- 特有功能（保护）：CF-Connecting-IP 提取、Cookie Bearer 提取、Invite/RegisterVerify/EmergencyAccessInvite/OrgApiKey/BasicJwt claims 结构。
- 不可接受差异及建议：
  1. **P1 Claims 字段不全**：[auth.rs:94-107](file:///d:/gitrepo/warden-worker/src/auth.rs#L94-L107) 仅 sub/exp/nbf/premium/name/email/email_verified/amr/security_stamp/device；VW `LoginJwtClaims` 另有 **iss、sstamp（字段名）、devicetype、client_id、scope**。建议补齐并命名对齐。
  2. **P1 refresh 机制不等价**（同 identity.rs，见上）。
- security stamp 校验语义等价；sstamp_exception（SSO 专用）无对应实现——SSO 未实现，可接受。

#### crypto.rs
- **状态：存在可接受差异**
- PBKDF2-HMAC-SHA256/32 字节等价（ring→pbkdf2 crate，hex→base64 内部自洽）；服务端密码盐 64 字节与 600k 默认迭代一致；argon2 不计算（VW 也仅用于 ADMIN_TOKEN，用户密码同为 PBKDF2）；hmac_sign/sha256_hex 本地实现等价；**P3** 附件 ID 用 `Uuid::new_v4()`（36 字符带横线）vs VW `generate_id`（20 位 hex）——客户端视为不透明字符串。

#### error.rs
- **状态：存在不可接受差异（HTTP 状态码全局不一致）**
- 可接受差异：错误 JSON 体字段（message/validationErrors/errorModel/error/...）与 VW `ApiErrorResponse` 一致。
- 不可接受差异：**P1 状态码映射**：[error.rs:90-121](file:///d:/gitrepo/warden-worker/src/error.rs#L90-L121) `NotFound→404`、`Unauthorized→401`、`Forbidden→403`；VW 业务 `err!` 默认 **400**，仅显式 err_code!/守卫失败才用其他码。大量"密码错误/资源不存在/越权"响应在两端状态码不同，横跨 accounts/ciphers/folders/sends/devices/2FA。建议：业务失败收敛回 400 语义（增加"默认 400"错误变体或逐端点调整）。

### 3.5 src/db

#### db/mod.rs
- **状态：存在可接受差异**。VW 为 Diesel 连接池/迁移/backup 基础设施（537 行）；当前仓库只保留 D1 `get_db`、`now_rfc3339_millis`、revision 更新（37 行）。纯框架适配。

#### db/models/archive.rs
- **状态：存在可接受差异**。无结构体，仅 save/delete 两个 D1 函数（表在 schema.sql）；`get_archived_at`/`find_by_user` 等价物在 API 层 sync 的 LEFT JOIN。

#### db/models/attachment.rs
- **状态：存在可接受差异**。字段映射 cipher_uuid→cipher_id 等；`attachment_to_json` 输出（id/url/fileName/size/sizeName/key/object）与 VW 完全一致（URL 用签名 token）。特有（保护）：r2_object_key、user_id 可空（组织附件语义）。

#### db/models/auth_request.rs
- **状态：存在不可接受差异（轻微）**。模型层只剩 purge_expired，数据流在 devices.rs；access_code 明文→**access_code_hash 哈希**（更安全）。不可接受：**P3 schema.sql 缺 `organization_uuid` 列**（组织设备审批/SSO 关联审批），与 SSO 未实现范围一致。

#### db/models/cipher.rs
- **状态：存在不可接受差异（轻微）**。手写 Serialize 输出与 VW to_json 完全一致（30+ 字段）；存储为 data JSON 列；favorite/folder_id 双写冗余列+关联表（读取以关联表为准）；权限 SQL 计算 access_edit/access_view_password。不可接受：**P3 org sync 时也输出 folderId/favorite/archivedDate/edit/viewPassword/permissions**（VW 仅 User sync 输出），客户端通常忽略。

#### db/models/collection.rs
- **状态：存在可接受差异**。to_json/to_details_json 一致；CollectionCipher 结构体缺失但 ciphers_collections 表存在，API 层处理。

#### db/models/device.rs
- **状态：存在不可接受差异**
- 可接受差异：字段映射（atype→device_type 等）；2FA remember 走 JWT 签名验证（remember_token_hash 列恒 NULL，isTrusted 恒 false 与 VW 一致）；设备 JSON 为超集（revisionDate/lastSeenDate/devicePendingAuthRequest）。
- 不可接受差异及建议：**P2 缺 `devices.refresh_token` 列语义**——VW 存设备级 OAuth refresh token，设备删除/更新即失效；当前 refresh 走全局 JWT（`jwt_keys` 表），**不校验设备行是否存在**，删除设备后 token 仍可续期。建议：refresh 流程增加设备存在性校验或携带设备版本号比对。

#### db/models/emergency_access.rs
- **状态：完全一致**（字段/常量/序列化逐一对齐：EMERGENCY_TYPE_VIEW=0/TAKEOVER=1、STATUS_INVITED=0...RECOVERY_APPROVED=4）。to_json_grantor/grantee_details 由 API 层实现。

#### db/models/event.rs
- **状态：存在不可接受差异（轻微）**。字段映射一致；EventType i32 常量值一致；输出含恒 null 的 policyId/providerId 等。不可接受：**P3 events 表缺 `policy_uuid` 及 provider_* 列**（Provider 未实现；policy 事件 policyId 恒 null）。

#### db/models/favorite.rs
- **状态：存在可接受差异**。方法一一对应；`set_favorite` 无条件 update_user_revision（VW 仅在状态变化时更新）——协议兼容。

#### db/models/folder.rs
- **状态：存在可接受差异**。FolderResponse 与 VW to_json 一致；FolderCipher 结构体缺失但表存在。

#### db/models/group.rs
- **状态：存在可接受差异**。to_json/to_json_details 一致；CollectionGroup/GroupUser 结构体缺失但关联表存在。

#### db/models/mod.rs
- **状态：存在可接受差异**。MembershipStatus Revoked 用 `REVOKE_OFFSET=128` 复刻 VW `ACTIVATE_REVOKE_DIFF=128`+Revoked=-1 语义；MembershipType Owner=0/Admin=1/User=2/Manager=3 与 client_type() 一致；枚举值逐一比对一致。

#### db/models/org_policy.rs
- **状态：存在可接受差异**。to_json 一致（type==8 时 canToggleState）；OrgPolicyType 值一致；DTO 移至 API 层。

#### db/models/organization.rs
- **状态：存在不可接受差异（轻微）**。to_json 字段逐一对应（seats/maxCollections/planType:6/usersGetPremium）；permissions 持久化（VW 为 TODO 硬编码，当前为超集）。不可接受：**P3 `useResetPassword` 硬编码 true**（VW 为 `mail_enabled()`；若通知通道未配置客户端会展示不可用的重置入口）；**P3 profile enabled 计算**（revoked 成员输出 false vs VW 恒 true）。

#### db/models/send.rs
- **状态：存在可接受差异**。字段映射一致；SendType Text=0/File=1、SendAuthType Password=1/None=2 一致；`send_to_json` 的 BASE64URL_NOPAD 编码输出字节一致。特有（保护）：r2_object_key/storage_type、send_file_chunks 分块表。

#### db/models/two_factor.rs
- **状态：存在可接受差异**。存储拆分：单表 twofactor → two_factor_authenticator/email/external/protected_action_otp 表；TwoFactorType 值一致；内部类型 1002 保留、1003/1004→webauthn_challenges 表、2000→protected_action_otp 表；恢复码 20 字节 BASE32 一致。特有（保护）：AES-GCM 加密 secret、last_used 时间步防重放。

#### db/models/two_factor_duo_context.rs
- **状态：存在可接受差异**。字段一致。特有（保护）：`take()` 用 DELETE...RETURNING 原子消费 state（VW 为两步 find+delete，当前更强，勿回改）。

#### db/models/two_factor_incomplete.rs
- **状态：存在可接受差异**。方法对应（INSERT OR IGNORE ≡ exists-check）；time_limit 默认 3 分钟与 VW 一致。

#### db/models/user.rs
- **状态：存在不可接受差异**
- 可接受差异：字段映射（akey→key、client_kdf_type→kdf_type 等）；verified_at/last_verifying_at→email_verified；external_id 无（SSO 未实现）；kdf_type 值一致；RegisterRequest 支持 2026.5 新格式+旧格式。特有（保护）：email_new_token_sent_at、ua_history 列。
- 不可接受差异及建议：
  1. **P2 缺 `users.stamp_exception`（UserStampException 2FA 豁免机制）**：VW 允许通过 2FA 的用户在 expire 时间内豁免特定路由（紧急访问查看/接管）的 stamp 校验；当前全程 verify_security_stamp，受保护操作每次需重新 2FA。建议：D1 增加短期 stamp exception（或等效临时 token）。
  2. **P3 缺 `users.enabled`（账号禁用）**：与未实现 admin 页面自洽，后续实现 admin 时补。

---

## 四、仅存在于目标仓库的文件汇总

见 1.4 节表格。重点：**admin.rs、sso.rs、sso_client.rs、db/models/sso_auth.rs 未实现**（仅客户端占位兼容，不宣称支持）；mail.rs→extensions/notify、storage.rs→r2_file.rs、ratelimit.rs→CF Rate Limiting 绑定、main.rs→lib.rs+entry.js、http_client.rs→fetch、db/schema.rs→sql/schema.sql 均有等价实现；query_logger.rs 无等价（影响低）。

---

## 五、根目录关键配置文件对比

### Cargo.toml（454 行 vs 78 行）
- **依赖裁剪与 Workers 兼容强相关**（可接受）：移除同步 IO/系统库（diesel、lettre、openssl、ring、reqwest 系、job_scheduler_ng、opendal、governor、openidconnect 等），替换为 wasm 密码学（p256/rsa/aes-gcm/hmac/pbkdf2/sha2/sha1/totp-rs/serde_cbor_2/ciborium）与 CF 平台绑定（worker/wasm-bindgen/web-sys）；框架 Rocket→Axum；webauthn-rs→worker_runtime/webauthn.rs 自研；yubico_ng/totp-lite→自研 fetch 实现；handlebars→手写/Assets。
- **需留意的语义缺口**：无 argon2 计算（VW 也只用于 ADMIN_TOKEN，不影响用户密码）；ID 生成器改为 uuid crate（P3）。
- Cargo.lock：双方都存在，与各自依赖集对应。

### 根目录结构完整性表

| 项 | vaultwarden | warden-worker | 归属 |
| --- | --- | --- | --- |
| Cargo.toml / Cargo.lock | 有（workspace+macros） | 有（cdylib, wasm） | 双方 |
| wrangler.jsonc / .cargo/config.toml | 无 | 有（CF 配置；getrandom_backend=wasm_js） | 仅当前 |
| .env.template / build.rs / diesel.toml / rust-toolchain.toml / rustfmt.toml | 有 | 无 | 仅目标 |
| Dockerfile / docker/ / .hadolint.yaml | 有 | 无 | 仅目标 |
| migrations/（sqlite/mysql/postgresql） | 有 | 无（已合入 sql/schema.sql，118 语句/38 表/41 索引） | 仅目标 |
| playwright/（E2E） | 有 | 无 | 仅目标 |
| resources/ | 有 | 无（在 static/web-vault/images） | 仅目标 |
| sql/schema.sql | 无 | 有（D1 完整基线） | 仅当前 |
| scripts/（cloudflare-provision、patch-webvault-turnstile） | 无 | 有 | 仅当前 |
| tests/（4 个 node 测试） | 无 | 有 | 仅当前 |
| static/（根） | 无（在 src/static） | 有（web-vault SPA） | 仅当前 |
| .github/workflows | build/release/hadolint/trivy/typos | push-cloudflare | 双方（用途不同） |
| README.md / LICENSE / .gitignore | 有 | 有 | 双方 |
| 其他 | SECURITY.md、macros/、.editorconfig 等 | .compat-reports/、memory.md | 双方各自 |

**发现配置残留（P3）**：[wrangler.jsonc:95](file:///d:/gitrepo/warden-worker/wrangler.jsonc#L95) `d1_databases[0].migrations_dir = "sql/migrations"` 指向已删除目录（当前只有 sql/schema.sql）。建议删除该字段或置空。

---

## 六、不可接受差异汇总表与处理建议（按优先级）

### P1（数据安全 / 契约等价，建议优先修复）

| # | 文件 | 差异 | 建议 |
| --- | --- | --- | --- |
| 1 | api/core/ciphers.rs | `/api/ciphers/purge` 忽略 organization 参数，组织清空请求会**误删个人保险库** | 解析并拒绝 organization 参数，或实现 Owner 版 `purge_org_vault` |
| 2 | api/core/accounts.rs | `SIGNUPS_VERIFY` 默认 true（VW 默认 false），未配邮箱时普通注册默认 401 | 默认改 false 或拆分 register/register-finish |
| 3 | auth.rs + identity.rs | Claims 缺 iss/sstamp/devicetype/client_id/scope；refresh token 无设备绑定/轮换/撤销，"删除设备后 token 仍可续期" | 补齐 Claims 字段并命名对齐；refresh 绑定 `devices.refresh_token` |
| 4 | error.rs + 各端点 | NotFound→404/Unauthorized→401 固定映射 vs VW 业务 err! 默认 400，跨 accounts/ciphers/folders/sends/devices/2FA | 业务失败收敛回 400 语义 |

### P2（功能缺口 / 权限语义）

| # | 文件 | 差异 | 建议 |
| --- | --- | --- | --- |
| 5 | events.rs / organizations.rs / ciphers.rs / accounts.rs | 服务端事件审计缺失（VW 20+ 处 log_event/log_user_event） | 补 log_event/log_user_event 及调用点；member events 改按 user 关联 |
| 6 | events.rs | `get_cipher_events` 无权限 404/403 vs VW 200 空列表 | 无权限返回空列表 |
| 7 | organizations.rs | `require_collection_manager` 额外要求 Manager access_all!=0 | 与 VW ManagerHeadersLoose 对齐 |
| 8 | accounts.rs | `post_delete_recover` 不发删除恢复邮件 | 补 action link 投递 |
| 9 | accounts.rs | `rotate_user_account_keys` 拒绝 emergency/recovery 数据 | 增加 key 更新分支 |
| 10 | accounts.rs / db/models/user.rs | stamp_exception 机制缺失（改密/2FA 豁免） | D1 短期 stamp exception 实现 |
| 11 | db/models/device.rs | 缺 devices.refresh_token 语义（与 #3 同源） | refresh 校验设备存在性 |
| 12 | two_factor/mod.rs | 删除最后 2FA 后不执行组织 2FA 策略吊销（enforce_2fa_policy 缺失） | 随组织策略模块接入禁用流程 |
| 13 | two_factor/authenticator.rs + mod.rs | `PasswordOrOtpData::validate` 硬编码 delete_if_valid=true，get→activate 同 OTP 流程第二步失败 | 恢复 delete_if_valid 参数 |
| 14 | api/icons.rs | 无 host 合法性/IP 校验、无正负缓存/fallback | 补域名格式校验与缓存策略 |
| 15 | api/identity.rs | `Key` 恒返回、`MasterPasswordPolicy` 恒空对象 | 随组织策略实现补齐 |
| 16 | api/notifications.rs | UpdateType 缺 SyncOrgKeys=6 | 随组织功能补齐 |
| 17 | api/core/meta/config.rs | `environment.sso` 为 null（VW 为 `""`）、featureStates 仅固定 1 项 | 对齐字符串与 feature flags 语义 |

### P3（可观察差异，多为状态码/细节）

- 状态码：folders.rs 404→400；emergency_access.rs 无效 token 401→400；two_factor 各文件密码失败 401→400；duo/yubikey 失败 401→400；events.rs 成员不存在 404→空列表。
- 细节：api/core/mod.rs 404 JSON catcher 缺失；cipher org sync 多余字段；organization.rs `useResetPassword`/`enabled` 计算；events 表缺 policy_uuid；auth_requests 缺 organization_uuid；user 表缺 enabled；crypto.rs 附件 ID 格式；批量上限更严（move 40/share 40/bulk 80）；软删/恢复返回体；push_auth_event deviceId null；email 2FA `enabled` 布尔 vs 字符串；webauthn challenge 缺 status/errorMessage；cron 缺失（purge_trashed_ciphers、event_cleanup_job、emergency_notification_reminder_job）；wrangler.jsonc migrations_dir 残留。

---

## 七、总体结论

1. **文件结构层面**：src 目录保持"同名主模块一一对应 + Workers 补充子模块拆分"的架构（accounts/devices.rs、ciphers/{attachments,sync}、meta/*、imports.rs、worker_runtime、extensions、crypto/password.rs、lib.rs/entry.js/heavy_do_routing.mjs 为当前仓库特有结构），Vaultwarden 独有文件（admin.rs、sso*.rs、mail.rs、storage.rs、query_logger.rs、src/static/** 等）均有明确去向或占位说明。
2. **内容层面**：45 对同名文件中仅 `db/models/emergency_access.rs` 完全一致；其余差异以**可接受的 Workers 兼容处理**为主（框架装配、D1/R2/DO、fetch、通知通道、子模块拆分、命名映射、更严格的安全加固）。**不可接受差异集中在 4 个 P1 契约点**（purge 误删风险、SIGNUPS_VERIFY 默认值、JWT Claims/refresh token 契约、HTTP 状态码全局映射）与若干 P2 功能缺口（事件审计、get_cipher_events、Manager 权限、stamp_exception、组织 2FA 策略、refresh 设备绑定、icons 校验、delete_if_valid）。
3. **特有功能保护**：Passkey、Turnstile、Webhook/Telegram/企业微信、D1/R2/DO 基础设施、Send access token、兼容别名、安全加固等均按"保护，勿改"标记，未纳入待修改差异。
4. **建议执行顺序**：先修 P1（purge 参数、注册默认值、Claims/refresh 契约、状态码收敛）→ 再补 P2（事件审计、权限语义、stamp_exception、组织 2FA 策略）→ P3 随组织功能与回归测试逐步对齐。所有改动遵循仓库维护约束：`cargo check --target wasm32-unknown-unknown`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets`、`node --test tests/*.test.mjs`、`worker-build --release` 全量验证。
