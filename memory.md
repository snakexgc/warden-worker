# Project Memory

> 本文件保存当前仓库经过代码与本地验证确认的长期上下文。
> 开始项目任务前应先读取并核验本文件，任务结束后应同步更新。

## 基本信息

- 项目名称：Warden Worker
- 项目路径：`D:\gitrepo\warden-worker`
- 上游仓库：`git@github.com:snakexgc/warden-worker.git`
- 当前分支：`main`
- 项目类型：面向个人、单用户部署的 Bitwarden 兼容 Cloudflare Workers 服务端
- Cargo 包版本：`1.3.0`
- Web Vault 版本：`2026.6.2`
- 主要技术栈：Rust 2024、WebAssembly、worker-rs、Axum、JavaScript、Cloudflare Workers、D1、R2、Durable Objects
- 数据与鉴权：SQLite/D1、JWT、PBKDF2-HMAC-SHA256、Argon2id 兼容、TOTP、WebAuthn
- 构建工具：Cargo、`worker-build`、Node.js、Wrangler
- CI 固定版本：Rust `1.97.0`、Wrangler `4.111.0`、`worker-build` `0.8.5`
- Worker 兼容日期：`2026-02-28`
- 构建命令：`node ./scripts/patch-webvault-turnstile.mjs && worker-build --release`
- 测试命令：
  - `cargo test`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt --all -- --check`
  - `node --test tests/*.test.mjs`
- 手动部署命令：`wrangler deploy`
- 最后更新时间：2026-07-22

## 项目概述

Warden Worker 将个人密码库服务部署到 Cloudflare 边缘环境，提供 Bitwarden 客户端和 Web Vault 所需的账户、认证、同步、密码项、文件夹、附件、Send、2FA、WebAuthn 与通知接口。D1 保存业务数据和密钥材料，R2 保存附件及 Send 文件，Durable Objects 分别承担实时通知和高 CPU 路由。

本项目不是 Vaultwarden 的逐行移植。兼容性工作应以客户端可观察行为为准，核对请求/响应结构、路由、状态码、版本与功能开关、同步 revision、通知副作用和数据迁移，而不能仅比较同名文件。

## 项目结构与文件职责

### 根目录与部署

- `README.md`
  - 部署、升级、Secrets、接口与通知配置说明。
- `Cargo.toml` / `Cargo.lock`
  - Rust 包元数据、依赖版本、Wasm 发布配置和 lint 规则。
- `wrangler.jsonc`
  - Worker 入口、Cron、变量、D1/R2/限流/DO 绑定、D1 增量迁移目录、日志、构建与静态资源配置。
- `.github/workflows/push-cloudflare.yaml`
  - 对 `main`、`uat`、`release*` 的无人值守首次部署与自动升级；执行预检、Cloudflare 资源创建或复用、真实 D1 ID 写入、新库基线初始化、待处理迁移、Worker 部署和健康检查。
- `scripts/cloudflare-provision.mjs`
  - 自动发现 Cloudflare 账户和 Workers 子域，精确创建或复用 D1/R2，并将真实 D1 `database_id` 更新到 Wrangler 配置。
- `scripts/patch-webvault-turnstile.mjs`
  - 构建前在 Web Vault 入口注入匿名 Send 的 Turnstile 导航保护；通过版本标记避免重复注入。
- `tests/cloudflare_provision.test.mjs`
  - 验证首次部署与升级时的 Cloudflare 资源发现、创建、复用和 D1 配置更新行为。
- `tests/deployment_workflow.test.mjs`
  - 验证 Workflow 的触发条件、权限、并发、固定工具链、数据库执行顺序与 DO 生命周期合约。
- `tests/heavy_do_routing.test.mjs`
  - 验证高 CPU/密码相关路径被分流到固定的 `personal-vault` HeavyDo。
- `static/web-vault/`
  - Wrangler Assets 发布的 Web Vault 构建产物；当前版本为 `2026.6.2`。
- `build/`、`target/`
  - 本地生成的 JS/Wasm 与 Rust 构建产物，不作为业务源码维护。

### `src`

- `src/entry.js`
  - Cloudflare JS 入口；规范化路径，将高 CPU 路由交给 `HEAVY_DO`，其余请求交给 Rust/Wasm Worker，并导出两个 DO 类。
- `src/heavy_do_routing.mjs`
  - HeavyDo 路由白名单和固定实例名规则。
- `src/lib.rs`
  - Rust Worker 的 `fetch`、`scheduled` 入口；初始化日志、D1/JWT/2FA 密钥、通知代理、CF 地理请求头、CORS 与 Axum Router。
- `src/api/router.rs`
  - Bitwarden/Vaultwarden 兼容 HTTP 路由总表和共享 `AppState`。
- `src/worker_runtime/heavy_do.rs`
  - `HeavyDo` 实现；复用同一套 Router，在 DO CPU 预算内执行密码验证等重计算请求。
- `src/api/notifications.rs`
  - `NotificationsHub` Durable Object、SignalR/WebSocket 协议处理，以及密码项、文件夹、Send、用户和认证请求的实时更新发布。
- `src/worker_runtime/background.rs`
  - 统一封装入口 Worker 的 `wait_until` 与 DO 内的异步后台任务。
- `src/api/core/`
  - HTTP 业务处理层，涵盖账户、身份令牌、同步、密码项、附件、文件夹、Send、导入、设备、设置、事件、兼容端点、2FA、WebAuthn、图标、CSS 与用量统计。
- `src/db/models/`
  - 用户、密码项、文件夹、Send、同步、导入和归档的数据结构、兼容反序列化及 API 序列化。
- `src/auth.rs`、`src/jwt.rs`、`src/worker_runtime/jwt_manager.rs`
  - Bearer/JWT 鉴权、令牌签发与 D1 中的 JWT 密钥管理。
- `src/password.rs`、`src/crypto.rs`
  - 服务端密码哈希、验证、旧哈希升级与客户端 KDF 参数校验。
- `src/worker_runtime/r2_file.rs`
  - 附件与 Send 共用的 95 MiB 限制、约 8 MiB 分片、R2 multipart abort/complete 和声明大小校验。
- `src/db/models/two_factor.rs`、`src/worker_runtime/two_factor_key_manager.rs`
  - TOTP/2FA 核心逻辑和 D1 加密密钥管理。
- `src/webauthn.rs`
  - WebAuthn/Passkey 凭据、挑战、登录验证与 PRF 支持。
- `src/extensions/notify/`
  - 企业微信、Telegram 通道、事件类型、模板、配置、上下文与分发器。
- `src/db/mod.rs`
  - D1 获取、统一毫秒时间戳和用户 vault revision 更新/读取。

### `sql`

- `sql/schema.sql`
  - 2026-07-22 统一后的完整数据库基线；已合并此前全部迁移的最终状态。包含 `DROP TABLE` 并清除 `d1_migrations`，对已有数据库执行会清空数据和迁移记录。
- `sql/migrations/`
  - 统一基线之后的 Wrangler 原生 D1 增量迁移目录；当前只有维护规则说明，未来按顺序新增 `.sql`，已应用文件不可修改、改名、重排或删除。

## 架构与关键流程

### HTTP 请求

1. Wrangler Assets 根据 `run_worker_first` 决定 API/动态路径先进入 Worker。
2. `src/entry.js` 规范化 URL；匹配 `src/heavy_do_routing.mjs` 的路径进入固定 `personal-vault` HeavyDo，其余进入 Rust Worker。
3. Rust 入口对 `/notifications/*` 直接代理到 `NotificationsHub`；普通请求初始化 D1、JWT 密钥和 2FA 密钥后进入 Axum Router。
4. `src/api/router.rs` 将请求分派到 `src/api/core/`；处理器调用模型、鉴权/密码/WebAuthn/2FA 模块并读写 D1 或 R2。
5. 成功的 vault 变更需同步更新用户 revision，并按业务需要发布实时通知。

### 高 CPU 密码路径

- 服务端密码 verifier 使用 PBKDF2-HMAC-SHA256，当前规则为 600,000 次迭代和独立随机 salt。
- 创建或验证 verifier 的路径必须经 `HEAVY_DO`，避免入口 Worker 的 CPU 限制。
- 本项目是单用户密码库，所有重计算请求共用固定的 `personal-vault` 实例；并发重计算可能短暂串行。
- 旧密码记录在成功验证后按当前格式渐进升级，不应将客户端 KDF 设置与服务端 verifier 规则混为一谈。

### 数据与文件

- D1 绑定名固定为 `vaultsql`，保存用户、密码项、文件夹、Send、设备、2FA/WebAuthn、JWT/2FA 密钥和附件元数据。
- R2 绑定名为 `SEND_FILES_BUCKET`，保存附件及 Send 文件二进制数据。
- 标准客户端单文件上限固定为 95 MiB；请求总 body limit 为 100,000,000 字节。文件达到 8 MiB 后使用 R2 multipart，下载由 JS 入口把 R2 流 pipe 到 `FixedLengthStream`，从而保持流式并让运行时生成正确的 `Content-Length`。
- `LOGIN_LIMITER` 与 `SEND_ACCESS_LIMITER` 分别保护登录和匿名 Send 访问。
- 每日 `0 3 * * *` Cron 调用 Send 清理逻辑，删除过期元数据和相关 R2 文件。

### 实时通知

- `NOTIFICATIONS_HUB` 承担 WebSocket/SignalR 连接与内部事件广播。
- vault 写操作的正确性不仅包括 D1 结果，还包括用户 revision 和相应的实时更新事件。
- `NotificationsHub` 使用 SignalR MessagePack 握手/二进制语义，每 15 秒通过 Durable Object alarm 发送 ping；宏必须使用 `#[durable_object]` 才会同时导出 WebSocket 与 alarm 回调。

### 部署与迁移

- `sql/schema.sql` 是 2026-07-22 统一基线；它会删除并重建项目表以及迁移追踪表，包括 D1 中的 JWT/2FA 密钥数据。执行前必须导出密码库并按需备份 D1/R2。
- 基线之后的数据库变更只新增到 `sql/migrations/`，`wrangler.jsonc` 的 `migrations_dir` 固定指向该目录；不要同时把增量写回 schema，否则新库会重复执行同一结构变更。
- GitHub Actions 对新库先导入 schema，再用 `wrangler d1 migrations apply` 应用全部增量；对已有库只应用 `d1_migrations` 未记录的文件。迁移失败会阻止后续 Worker 部署。
- `sql/d1-migrations/` 已确认不再需要并删除；工作流不再包含历史列探测或硬编码旧迁移。
- 执行任何数据库操作前必须确认 `--local`/`--remote` 和目标数据库；已发布迁移不得修改、改名、重排或删除。

## 特殊事项与项目约束

- 项目定位是个人单用户密码库；`users_single_user_before_insert` 触发器是数据库层最终约束，注册处理也应在昂贵哈希前快速拒绝第二个用户。
- 不得在仓库、日志或 `memory.md` 中记录 API Token、Webhook、Bot Token、Turnstile Secret 或用户密码。
- `DOMAIN` 是可选的公开域名覆盖；未设置时附件/Send 使用相对 URL，WebAuthn 从请求头推导 Origin 与 RP ID。若显式设置自定义域名，应与真实 HTTPS Origin 一致。
- `wrangler.jsonc` 中的 D1、R2、DO、Assets 与路由意图不能为了消除配置漂移警告而随意删除。
- Workers 本地模拟器通过不等于生产路由通过；生产故障应优先检查部署版本和远程日志。
- 上游兼容合并必须先确认本地路由、数据模型和 Workers/DO 调用链是否适用，不能机械 cherry-pick Vaultwarden 原生实现。
- Turnstile 匿名 Send 门禁、Workers 架构和本地令牌设计可能构成有意的上游差异；除非完成行为级审计和真实客户端验证，不应声称“完全等同 Vaultwarden”。
- 历史上用户在后端同步任务中明确要求过 `static/**` 由其自行维护；只有任务再次包含该范围约束时才视为硬边界，不能擅自推广为所有任务的永久规则。
- 本机 PowerShell 显示中文异常时先用 `Get-Content -Encoding utf8` 复核，不要直接判定文件损坏。
- 本机访问 Cloudflare API 时可能需要显式设置 `HTTP_PROXY`、`HTTPS_PROXY` 与 `ALL_PROXY`；是否需要应按当次网络状态验证。

## 当前项目状态

- 分支/提交：`main`，本次任务开始时 HEAD 为 `3017b480c8d3aa849fc64cd27356de4094780593`（“修复编译报错”），工作树干净。
- Vaultwarden 最新三次提交审阅基线：`D:\gitrepo\vaultwarden` 的 `660faee68e3406d33244b67eadc18524c47674c2`（2026-07-21）。
- Bitwarden Android 对照基线：`C:\Users\MINI\AppData\Local\Temp\bitwarden-android-2026.6.1-bwpm` 的 `2026.6.1` 客户端实现。
- 2026-07-22 已实施审计确认的个人密码库兼容性修复；业务代码、schema、配置、测试和文档均有改动，静态 Web Vault 未改变。
- 当前实现覆盖账户认证、密码库同步、Ciphers、Folders、附件、Send、导入、设备、2FA、WebAuthn、实时通知和动态 Vaultwarden CSS。
- 最近主要变化：
  - 将 worker-rs/worker-build 升级到 `0.8.5`、Wrangler 升级到 `4.111.0`，并刷新低风险直接依赖和完整锁文件。
  - GitHub Actions 的 Rust 工具链固定为已验证的 `1.97.0`，避免移动的 `stable` 引入未验证 lint 后使部署突然失败。
  - 本机全局 Wrangler CLI 已从 `4.104.0` 升级到 `4.111.0`，与 GitHub Actions 固定版本一致。
  - 动态 Vaultwarden CSS 的 Custom Role 规则同时兼容 `<bit-dialog>` 与 `[bit-dialog]` 两种新版 Web Vault DOM 形态。
  - Cipher `cipherDetails` 响应已移除上游废弃的顶层 `data` 兼容字段，类型数据继续由 `login`、`secureNote`、`card`、`identity`、`sshKey` 等标准字段返回。
  - 增加附件 API 与附件元数据迁移。
  - 加强新版 Bitwarden 客户端的 Cipher key、请求字段、序列化、revision 与通知兼容。
  - 历史 SQL 已收敛到 `sql/schema.sql` 基线；后续顺序迁移统一由 `sql/migrations/` 和 Wrangler `d1_migrations` 追踪。
- 2026-07-22 已修复邮箱规范化、Token form 别名与 refresh 设备继承、profile/密码策略/config/密码提示响应、Email 2FA 鉴权与版本分支、TOTP 重放、设备 404/clear-token、健康检查、通知 keepalive 和文件流式 multipart 等已确认偏差。
- Bitwarden/Vaultwarden API 错误体字段现为 `validationErrors`、`errorModel`、`exceptionMessage` 等 camelCase；OAuth `error_description` 保持规范名称。
- 组织管理、SSO 与 Push 仍按项目边界不实现；组织字段保持兼容空值，Push 的设备 token 端点仅保持兼容语义。
- `two_factor_authenticator.last_used` 已直接包含在唯一 schema 中；本次不提供保留旧 D1 数据的原地升级路径。
- 尚未验证：
    - 未部署到 Cloudflare，未检查远程 Worker 版本、绑定、D1/R2 实际状态或远程日志。
    - 未执行真实 Bitwarden Android/Desktop/Web 客户端端到端验证。
    - 未做远程大文件上传/下载、生产 Durable Object alarm 或完整旧版本客户端矩阵验证。

## 需求与修改记录

### 2026-07-17：使用 Memory 技能初始化仓库

#### 用户需求

使用 Memory 技能初始化当前 `warden-worker` 仓库。

#### 需求分析

- 仓库根目录此前不存在 `memory.md`。
- 初始化必须以当前代码、配置和测试为准，并保留已经验证且仍适用的项目历史约束。
- 只建立长期项目上下文，不修改业务逻辑、部署配置或数据库。

#### 修改内容

- 分析 README、Cargo/Wrangler 配置、JS/Rust 入口、Router、核心模块、D1 schema/迁移、GitHub Actions、测试和最近提交。
- 创建根目录 `memory.md`，记录项目结构、请求流、数据流、部署迁移规则、兼容性边界、当前状态和验证结果。

#### 涉及文件

- `memory.md`

#### 修改结果

仓库已建立可供后续任务读取和持续维护的项目级长期记忆。

#### 验证情况

- `cargo test`：通过，48 passed，0 failed。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：通过，3 passed，0 failed。
- `worker-build --release`：通过，生成 Wasm/JS 构建产物。
- `git diff --check`：通过。
- 未进行生产环境部署或真实客户端验证。

#### 特殊事项

- 本机验证工具版本为 Rust/Cargo `1.96.0`、Node.js `v24.18.0`、`worker-build 0.8.5`、Wrangler `4.104.0`；CI 使用上方固定版本，不能把本机版本误记为 CI 版本。

#### 遗留事项

- 无阻塞遗留项；后续每次项目任务完成后继续更新本文件。

### 2026-07-17：在不改变项目功能的前提下升级依赖

#### 用户需求

升级项目依赖包，同时保证现有项目功能不受影响。

#### 需求分析

- 优先更新 Cargo 当前兼容范围内的直接和传递依赖，并将 worker-rs、worker-build 与 Wrangler 对齐到当前稳定版本。
- 对 API 已保持兼容且能被现有测试覆盖的依赖采用新版本。
- `aes-gcm`、`sha2`、`hmac`、`pbkdf2`、`p256` 和 `rand` 的下一主版本涉及加密协议或随机数 API，未在本次一般依赖升级中跨主版本，避免产生无法由现有单元测试完全覆盖的行为变化。
- 不更新 `compatibility_date`，不新增兼容性 flag，不修改业务源码、数据库 schema、路由或静态资源。

#### 修改内容

- 将 `worker` 与 `worker-macros` 从 `0.8.1` 升级到 `0.8.5`。
- 将 `tower-http` 升级到 `0.7.0`、`base64` 升级到 `0.22.1`、`constant_time_eq` 升级到 `0.5.0`、`thiserror` 升级到 `2.0.18`。
- 提升 Axum、Serde、Chrono、UUID、TOTP、getrandom、日志及其他低风险直接依赖的最低版本。
- 运行 `cargo update`，刷新 `Cargo.lock` 中 worker-rs/Wasm 和其他兼容的传递依赖。
- 将 GitHub Actions 的 Wrangler 固定版本从 `4.73.0` 提升到 `4.111.0`，将 `worker-build` 从 `0.8.1` 提升到 `0.8.5`。

#### 涉及文件

- `Cargo.toml`
- `Cargo.lock`
- `.github/workflows/push-cloudflare.yaml`
- `memory.md`

#### 修改结果

项目现在使用 worker-rs/worker-build `0.8.5` 和 Wrangler `4.111.0`；Cargo 当前版本约束下已无可继续更新的包。升级未要求修改 Rust/JavaScript 业务源码。

#### 验证情况

- `cargo test`：通过，48 passed，0 failed。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：通过，3 passed，0 failed。
- `worker-build --release`（`0.8.5`）：通过。
- `npx --yes wrangler@4.111.0 deploy --dry-run`：通过；正确识别 D1、R2、两个 Durable Objects、两个 Rate Limiters、变量和 335 个静态资源，未部署远程资源。
- Turnstile 构建补丁检测到当前 v2 标记并保持 `static/web-vault/index.html` 不变。
- `cargo update --dry-run`：0 个可在当前约束下继续更新的包。
- `git diff --check`：通过，仅有 Windows 行尾转换提示。
- 未进行生产环境部署或真实客户端验证。

#### 特殊事项

- worker-rs 与 worker-build 应保持同一发布代际；Wasm 相关的 `wasm-bindgen`、`js-sys`、`web-sys` 和 `wasm-bindgen-futures` 也应作为一组核验。
- 后续若升级上述密码学/随机数依赖的下一主版本，应单独执行协议向量、旧数据读取、TOTP、WebAuthn 和真实客户端回归，不应混入普通补丁更新。

#### 遗留事项

- 无阻塞遗留项；密码学/随机数依赖的下一主版本可在具备更完整端到端测试时单独评估。

### 2026-07-17：同步升级本机 Wrangler 到 4.111.0

#### 用户需求

确认 Wrangler 最新版本为 `4.111.0`，并将其一并升级。

#### 需求分析

- GitHub Actions 的 `WRANGLER_VERSION` 已在上一任务中升级到 `4.111.0`。
- 本机全局 Wrangler 仍为 `4.104.0`，需要与项目 CI 版本对齐。
- 项目没有 `package.json`，无需为全局 CLI 升级额外引入 Node.js 项目依赖文件。

#### 修改内容

- 执行 `npm install -g wrangler@4.111.0`，升级本机全局 Wrangler。
- 核验 `.github/workflows/push-cloudflare.yaml` 继续固定使用 `4.111.0`。

#### 涉及文件

- `memory.md`
- `.github/workflows/push-cloudflare.yaml`（仅核验，版本修改已由上一任务完成）

#### 修改结果

本机全局 Wrangler 与 GitHub Actions 现在都使用 `4.111.0`，没有新增 `package.json`，也没有改变 Worker 配置或业务代码。

#### 验证情况

- `npm view wrangler version`：返回 `4.111.0`。
- `wrangler --version`：返回 `4.111.0`。
- 全局 `wrangler deploy --dry-run`：通过；release 构建成功，正确识别 D1、R2、两个 Durable Objects、两个 Rate Limiters、环境变量和 335 个静态资源。
- Turnstile 构建补丁检测到现有 v2 标记，没有修改 `static/web-vault/index.html`。
- 未部署远程资源。

#### 特殊事项

- npm 安装提示 `esbuild`、`workerd`、`sharp` 的安装脚本尚未列入 `allowScripts`；当前 Wrangler 版本检查和 dry-run 均已通过，因此本次未额外执行脚本授权。

#### 遗留事项

- 无。

### 2026-07-22：按端点审计 Vaultwarden/Bitwarden 兼容性

#### 用户需求

从 HTTP 端点入手，将本项目与本机 Vaultwarden 源码逐项比较；允许项目特殊功能和组织管理能力不同，但要求个人密码库逻辑及数据格式兼容 Bitwarden。

#### 审计基线与范围

- Warden Worker：`f9141b45ded9cd1086a562c0d1a732119f6200b5`。
- Vaultwarden：`169aa5efcc8d94684ff3bc813a00e6bcc0cc537a`。
- 对照路由、认证/账户、设备、同步、Cipher/Folder、导入、附件、Send、2FA/WebAuthn、通知、配置和健康检查；排除组织管理、SSO 和项目明确的 Turnstile/通知通道/单用户架构差异。

#### 已确认结论

- 不能确认完全兼容。个人密码库主要路由覆盖和 Cipher/Folder/Send/附件的核心 API 序列化总体对齐；组织字段保持空数组或 `null`，符合当前无组织能力的边界。
- `prelogin` 未规范化邮箱，而注册和密码登录会转小写；大小写或首尾空格不同会返回错误 KDF 参数，导致客户端派生错误的主密码哈希。
- `/api/accounts/profile` 缺少 Vaultwarden profile 中的 `_status`、`providers`、`providerOrganizations`、`forcePasswordReset`、`usesKeyConnector`、`creationDate`；`verify-password` 返回 `{}`，而 Vaultwarden 返回主密码策略。
- 密码提示对未注册邮箱返回 404、对已注册邮箱返回 200，形成账号枚举；Vaultwarden 在可发邮件时刻意统一成功行为。
- `/api/two-factor/send-email-login` 在按邮箱调用时允许既无主密码哈希、也无经校验的 AuthRequest 凭据，并且未使用登录限流；旧客户端仅有 Email 2FA 时登录错误响应也不会像 Vaultwarden 那样自动发码。
- TOTP 验证只校验当前时间窗，未像 Vaultwarden 一样持久化 `last_used` 阻止同一时间步重复使用。
- `clear-token` 清除的是 2FA remember token，而 Vaultwarden 该端点只清 push token；读取不存在的 device 会创建记录，而 Vaultwarden 返回不存在错误。
- 根 `/alive` 和 HEAD `/alive` 缺失；`/api/alive` 只返回时间，不像 Vaultwarden 同时验证数据库连接。
- 通知 Durable Object 没有 Vaultwarden 的 15 秒 WebSocket keepalive/ping；当前 Web Vault 内置 SignalR 默认 server timeout 为 30 秒，空闲连接行为没有对等保证。
- 附件和 Send 文件上传、R2 下载会把整个文件读入 `Vec`/`bytes`；路由宣称 1 GiB body limit，但 Cloudflare Worker isolate 只有 128 MB 内存且入口请求体还有套餐上限，因此大文件路径与宣称不一致。
- refresh token 路径从请求体而不是 refresh token/设备记录恢复 device identifier；请求未携带该字段时新 token 会丢失设备上下文。Token form 对 Vaultwarden 支持的部分无大小写/无下划线别名也未覆盖。
- `/api/config` 固定 `disableUserRegistration=false`，与单用户数据库约束在首个用户注册后不一致。

#### 验证情况

- `cargo test --all-targets`：通过，48 passed、0 failed。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：通过，3 passed、0 failed。
- `worker-build --release`：通过。
- 未执行远程部署、生产 D1/R2 检查或真实 Bitwarden 客户端端到端回归。

#### 涉及文件

- 业务代码仅审计，未修改。
- `memory.md`：记录审计基线、结论、验证和后续项。

### 2026-07-22：实施 Bitwarden/Vaultwarden 个人密码库兼容性修复

#### 用户需求

以 Vaultwarden `169aa5e` 和 Bitwarden Android `2026.6.1` 为行为与数据契约基线，修复审计发现的全部个人密码库问题；保留单用户、Workers/D1/R2/DO、Turnstile、Webhook/Telegram/企业微信通知，以及不实现组织管理、SSO、Push 和 SMTP 的项目边界。

#### 修改内容

- 认证与账户：统一邮箱 `trim + lowercase`；Token form 键按无大小写、忽略下划线解析并支持 Android/iOS 别名；非数字 iOS device type 回退为 14；refresh 从 claim 继承设备且只输出标准字段；补全 profile、密码策略、动态注册开关、同态密码提示和 Vaultwarden camelCase 错误模型。
- 2FA 与设备：Email 登录发码端点增加独立限流和主密码/AuthRequest 校验；仅 2025.5 前客户端自动发 Email 码；TOTP 通过 D1 `last_used` 条件更新原子消费时间步；设备读取/Push token 更新对不存在记录返回 404，`clear-token` 不再清除 remember token。
- 健康检查与通知：根 `/alive` 和 `/api/alive` 的 GET/HEAD 均执行 `SELECT 1`；Assets 增加 `/alive` 与 `/two-factor/*` Worker 优先路由；NotificationsHub 回显二进制消息，并在存在连接时每 15 秒发送 MessagePack ping，最后连接关闭后删除 alarm。
- 文件：附件和 Send 共用 95 MiB 限制、100,000,000 字节请求上限及约 8 MiB R2 multipart 流程；失败会 abort，元数据提交失败会清理对象；下载直接转交 R2 `ReadableStream`，JS 入口再用 `FixedLengthStream` 保留流式并生成 `Content-Length`，不再全量 `bytes()`。
- 数据：`sql/schema.sql` 增加 `two_factor_authenticator.last_used`；当时新增过顺序迁移，随后在同日的 schema-only 基线收敛任务中并入唯一 schema 并删除。
- 文档：README 增加迁移先于代码部署、文件限制和流式存储说明；本文件同步长期行为与验证结果。

#### 涉及文件

- `src/entry.js`、`src/auth.rs`、`src/error.rs`、`src/lib.rs`、`src/api/router.rs`、`src/api/notifications.rs`、`src/db/models/two_factor.rs`、`src/worker_runtime/r2_file.rs`、`src/webauthn.rs`
- `src/api/core/accounts.rs`、`attachments.rs`、`config.rs`、`devices.rs`、`identity.rs`、`sends.rs`、`two_factor.rs`
- `sql/schema.sql`（当时还新增过、现已删除的 TOTP 顺序迁移）
- `wrangler.jsonc`、`README.md`、`memory.md`

#### 本地验证

- `cargo test --all-targets`：57 passed、0 failed；包含邮箱、Token form、profile、refresh、客户端版本边界、TOTP 时间步、文件限制与错误模型合约。
- `cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`git diff --check`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：3 passed、0 failed。
- `worker-build --release` 与 Wrangler `4.111.0 deploy --dry-run`：通过；dry-run 识别 335 个 Assets、D1、R2、两个 DO、两个限流绑定，未部署。
- 本地 D1 迁移：当前 schema 与模拟旧 schema 两种路径均通过，旧 TOTP 记录保留并得到 `last_used=0`。
- 本地 HTTP/D1/R2/DO：健康检查、动态 config、Token 别名/iOS、profile、密码提示同态延迟、设备 404/clear-token、Email 2FA 鉴权/限流/版本分支、refresh 设备继承均通过。
- TOTP 实际启用后跨时间步登录：首次 200，同码重放 400；验证了 D1 原子消费。
- WebSocket：SignalR 握手和自定义二进制消息回显成功，约 15 秒与 30 秒分别收到 MessagePack ping。
- 文件：16 B 与 17 MiB+ 文件的附件上传/下载/删除通过；17 MiB+ Send 多分片上传/回读/删除通过，SHA-256 一致；声明超限和实际超限均为 413，实际超限 abort 后对象下载为 404；附件与 Send 下载均实测返回正确 `Content-Length`，内部桥接头不会泄漏。

#### 特殊事项与遗留

- 当时的迁移先于代码要求已被后续 schema-only 基线取代；当前升级方式是备份后用完整 schema 手动重建。
- 未部署 Worker，未执行远程 D1 迁移或远程 D1/R2/DO 验证；本地通知使用无效占位 Webhook，后台投递失败符合测试配置且未改变现有通知实现。
- 未运行真实 Android 2026.6.1 UI 端到端或 Desktop/Web/iOS/CLI 客户端矩阵；当前结论限于源码契约、单元测试和本地 HTTP/存储/DO 验证。

### 2026-07-22：将 D1 SQL 收敛为唯一当前基线

#### 用户需求

确认所有历史升级 SQL 的最终结构均已正确进入 `sql/schema.sql`，随后删除除该文件以外的全部 SQL；数据库直接对齐到当天状态。本次由用户手动部署，不要求自动部署兼容或保留旧库原地升级能力。

#### 修改内容

- 逐一核对 17 个历史兼容迁移和 2 个 Wrangler 顺序迁移：KDF、密码 salt/迭代数、账号兼容列、单用户触发器、设备/认证请求、TOTP/Email/WebAuthn 2FA、保护操作 OTP、归档、Cipher key/附件、Send R2 字段及相应索引均已由完整 schema 表达。
- `schema.sql` 的清理段补充旧版 `two_factor_webauthn_challenges`、两个迁移临时表，以及当前 `jwt_keys`/`two_factor_keys`，确保重建不会残留旧表、临时表、旧列或密钥数据。
- 删除 `sql/d1-migrations/` 和 `sql/migrations/` 下全部 19 个 SQL 文件；仓库现在只有 `sql/schema.sql`。
- 从 `wrangler.jsonc` 删除已不存在的 `migrations_dir`；README 改为 schema-only、手动、破坏性重建流程。
- 按用户明确范围保留 `.github/workflows/push-cloudflare.yaml` 原状；其旧库迁移步骤仍引用已删除 SQL，因此本次不能用于自动数据库升级。

#### 本地验证

- Wrangler `4.111.0` 在隔离的本地 D1 中连续两次执行完整 schema，均为 57 条命令成功。
- 人工加入旧版 WebAuthn/迁移临时表、遗留列和 JWT/2FA 密钥数据后再次执行 schema：最终为 18 个项目表，遗留表 0、遗留列 0、两张密钥表记录均为 0。
- `PRAGMA foreign_key_check` 返回空结果；关键字段检查为 users 历史兼容列 10/10、Cipher key 1/1、Send R2 列 2/2、TOTP `last_used NOT NULL DEFAULT 0` 1/1。
- D1/Miniflare 拒绝 `PRAGMA integrity_check`（`SQLITE_AUTH`）；这不是 schema 执行错误，已由重复导入、对象清单、关键列与外键检查覆盖。
- `cargo test --all-targets`：57 passed、0 failed；`cargo fmt --all -- --check`、严格 clippy、3 个 Node 路由测试均通过。
- Wrangler `4.111.0 deploy --dry-run` 和 release Worker 构建通过，识别 335 个 Assets、D1、R2、两个 DO 与两个限流绑定，未远程部署。

#### 特殊事项与遗留

- 未操作远程 D1、R2 或 Worker；手动远程执行 `schema.sql` 会清空密码库及 D1 密钥，必须先导出和备份。
- 该任务当时按用户要求未修改 GitHub Actions；随后同日任务已恢复面向未来 `sql/migrations` 的自动增量迁移。

### 2026-07-22：恢复统一基线之后的 D1 自动增量迁移

#### 用户需求

统一当前数据库基线后，后续数据库升级 SQL 放入 `sql/migrations` 并由自动部署执行；修改 GitHub Actions，并确认不再使用的 `sql/d1-migrations` 是否可以删除。

#### 修改内容

- `wrangler.jsonc` 将 `migrations_dir` 指向 `sql/migrations`；新增该目录的维护说明，约定从 `0001_*.sql` 开始顺序编号且已应用文件不可变。
- GitHub Actions 删除所有硬编码历史 SQL、列探测和旧库兼容步骤；存在 `sql/migrations/*.sql` 时在 Worker 部署前运行 `wrangler d1 migrations apply --remote`，没有 SQL 时显式跳过。
- 基础设施 job 获取真实 D1 ID 后立即更新本 job 的 `wrangler.jsonc`，避免新建数据库时 schema 或迁移命令误用仓库中的旧 ID；deploy job 原有的 ID 同步仍保留。
- 新数据库的顺序固定为“导入 2026-07-22 schema 基线 → 应用全部增量迁移 → 部署 Worker”；已有数据库只应用 `d1_migrations` 尚未记录的文件。
- `schema.sql` 增加清理 `d1_migrations`，保证本次手动破坏性对齐后从干净的迁移序列开始；确认并删除空的 `sql/d1-migrations` 目录。
- README 说明本次手动基线对齐与后续自动增量升级的边界。

#### 本地验证

- Wrangler `4.111.0` 和本地 config schema 均确认支持 D1 binding 的 `migrations_dir`；Cloudflare 官方文档确认迁移文件按顺序应用并记录在 `d1_migrations`。
- 空 `sql/migrations` 的 `wrangler d1 migrations list --local` 返回 “No migrations to apply” 且退出码为 0。
- 临时加入 `0001_ci_validation.sql` 后，本地首次 apply 成功，第二次返回无待处理迁移；测试数据与追踪记录均为 1，证明同一文件只执行一次。验证后已删除临时 SQL，目录仅保留说明文件。
- 再次执行 schema 后 `d1_migrations` 表数量为 0，确认本次手动基线会清理旧迁移状态。
- PyYAML 成功解析 Workflow，并确认 D1 ID 同步、schema 初始化、应用迁移和空目录跳过步骤的顺序与 `hashFiles('sql/migrations/*.sql')` 条件正确；工作流和 Wrangler 配置中无旧迁移路径或硬编码历史 SQL 引用。
- `git diff --check` 通过；Wrangler `deploy --dry-run` 和 release Worker 构建通过，识别 335 个 Assets、D1、R2、两个 DO 与两个限流绑定，未远程部署。

#### 特殊事项与遗留

- 未执行远程迁移或部署；现有生产库必须先按 README 完成本次手动基线对齐，之后才能依赖新的自动增量流程。
- 基线后的变更只进入迁移目录，不同步回 schema；若未来再次合并基线，需要另行安排破坏性重建和迁移链重置。

### 2026-07-22：统一首次部署与后续自动升级 Workflow

#### 用户需求

全面确认自动部署脚本同时支持两条无人值守路径：只提供 Cloudflare API Token 的全新部署，以及指定分支出现新提交后的自动升级；重点保证 D1 的真实 `database_id` 会被正确填入部署配置。

#### 修改内容

- Workflow 改为单一串行的“资源准备 → 测试/dry-run → schema/迁移 → 部署 → 健康检查”任务；私有仓库显式授予 `contents: read`，移除会修改远程资源的 PR 触发，保留 `main`、`uat`、`release*` push 和手动触发。
- 同一仓库的所有部署共用固定并发组且 `cancel-in-progress=false`，避免不同分支同时修改同一 D1/R2/Worker，或新提交在迁移中途取消旧任务。
- 唯一必选 Secret 改为 `CLOUDFLARE_API_TOKEN`。Token 只可见一个账户时自动发现 Account ID；多账户 Token 才需要可选的 `CLOUDFLARE_ACCOUNT_ID`，且歧义时安全失败而不猜测目标账户。
- 新增 `scripts/cloudflare-provision.mjs`：使用 Cloudflare JSON API 精确查找/创建 Workers 子域、`vaultsql` D1 和 `warden-send-files` R2；未注册 Workers 子域兼容 API 错误码 `10007` 并用完整 Account ID 生成确定性名称，避免 Wrangler 交互提示。
- D1 查找按完整名称匹配且支持分页；新建后再按返回 UUID 查询一次并核验名称/ID。随后只更新 `wrangler.jsonc` 中 `binding=vaultsql` 的对象，部署前再次验证 `database_id` 已等于 Cloudflare 返回值，不再使用人类可读输出、模糊 grep、全局 sed 或吞掉 API 错误。
- 新 D1 仅执行一次 `schema.sql`，然后应用全部增量迁移；已有 D1 跳过 schema，只应用 `sql/migrations` 中未记录的迁移。release dry-run 在任何远程数据库变更之前完成，迁移成功后才执行真实 deploy。
- 删除原 Workflow 中直接 PATCH Worker settings/DO bindings 的逻辑以及重复的首次/已有 Worker 部署分支；Durable Objects 生命周期继续由 `wrangler.jsonc` 的既有 SQLite migrations 和单次 `wrangler deploy` 原生处理。
- `wrangler.jsonc` 显式设置 `workers_dev=true`；部署后对自动得出的 workers.dev URL 重试根 `/alive`。README 同步记录单 Secret 权限、可选 Account ID、首次与升级流程、真实 `database_id` 行为和旧基线的一次性人工边界。

#### 本地验证

- 新增 16 项部署辅助/Workflow 合约测试，与既有 3 项 HeavyDo 路由测试合计 `node --test tests/*.test.mjs` 为 19 passed、0 failed。
- 首次部署 API 模拟确认会创建 Workers 子域、D1、R2，复核新 D1 UUID，写入 `database_id` 并输出 `d1_is_new=true`；升级模拟确认零 POST/PUT、资源全部复用且输出 `d1_is_new=false`。
- `actionlint` 对 Workflow 无错误；PyYAML 成功解析 17 个步骤；静态合约确认 schema、migration、真实 deploy 顺序正确，且无 PR 远程部署、`sed -i`、`|| true`、`wrangler-action` 或 DO settings PATCH。
- `cargo test --all-targets`：57 passed、0 failed；`cargo fmt --all -- --check`、`cargo clippy --all-targets -- -D warnings`、`git diff --check` 均通过。
- Wrangler `4.111.0 deploy --dry-run` 和 release Worker 构建通过，识别 335 个 Assets、D1、R2、两个 SQLite DO、两个限流绑定及 `workers_dev` 路由；未执行远程部署或远程资源写入。

#### 特殊事项与遗留

- 本地没有使用真实 Cloudflare Token，因此未实际创建/复用远程 Account/D1/R2/Workers 子域，也未运行远程 `/alive`；这些由首次真实 Actions 运行验证。
- Token 应将 Account Resources 限定为唯一目标账户，并包含 Account Settings Read、Workers Scripts Edit、D1 Edit、Workers R2 Storage Edit。旧式 Global API Key 需要邮箱，不属于单 Secret 自动流程。
- 2026-07-22 统一基线之前创建且尚未手动对齐的旧 D1，仍须按 README 先完成一次基线重建；全新数据库和已对齐数据库之后可完全自动升级。

### 2026-07-22：修复 Rust 1.97 CI 的 `manual_filter` 失败

#### 用户需求

修复 GitHub Actions 在 Rust 1.97 严格 Clippy 检查中报告的 `clippy::manual_filter` 错误，恢复自动部署脚本运行。

#### 原因与修改内容

- Workflow 原来安装移动的 `stable` 工具链；本地 Rust 1.96 未报告该 lint，而 CI 升到 Rust 1.97 后因 `-D warnings` 将其视为编译错误。
- `src/db/models/cipher.rs` 将手写的 `Option::and_then` 空字符串筛选改为 `Option::filter`；缺失值、空字符串和非空字符串的反序列化语义保持不变。
- Workflow 新增 `RUST_TOOLCHAIN: 1.97.0` 并按该版本安装/设为默认，避免后续 `stable` 漂移造成未经验证的 CI 变化。
- `tests/deployment_workflow.test.mjs` 新增固定 Rust 工具链的静态合约测试，并禁止恢复 `rustup toolchain install stable`。

#### 涉及文件

- `src/db/models/cipher.rs`
- `.github/workflows/push-cloudflare.yaml`
- `tests/deployment_workflow.test.mjs`
- `memory.md`

#### 本地验证

- `cargo +1.97.0 clippy --all-targets -- -D warnings`：通过，已复现并消除用户日志中的失败点。
- `cargo +1.97.0 test --all-targets`：57 passed、0 failed。
- `cargo +1.97.0 fmt --all -- --check`：通过。
- `node --test tests/*.test.mjs`：20 passed、0 failed。
- `actionlint .github/workflows/push-cloudflare.yaml` 与 `git diff --check`：通过。
- 未重新运行远程 GitHub Actions，也未部署 Worker 或修改远程 Cloudflare 资源。

### 2026-07-22：审阅 Vaultwarden 最近三次提交并同步适用修复

#### 用户需求

确认 `D:\gitrepo\vaultwarden` 最近三次提交的修改内容，检查当前 `warden-worker` 是否存在相同问题，存在时予以修复。

#### 审阅结论

- `660faee6`（Fix custom role dialog selectors）：Vaultwarden 将 Custom Role 隐藏规则的根选择器从 `bit-dialog` 扩展为 `:is(bit-dialog, [bit-dialog])`，兼容新版 Web Vault 的属性式 dialog DOM。当前仓库存在相同旧选择器，问题适用。
- `683a23e4`（Fix compilation with newer `rust-musl` version）：Vaultwarden 的 Alpine Docker 构建将写入 `CARGO_TARGET` 的来源从 `RUST_MUSL_CROSS_TARGET` 改为新版镜像提供的 `CARGO_BUILD_TARGET`。当前仓库没有 Dockerfile、musl 构建目标或这些环境变量，使用 Cloudflare Wasm 构建链，问题不适用。
- `4a9bcb06`（Remove old compatibility code）：Vaultwarden 删除 `cipherDetails` 响应中重复类型数据及 `name`、`notes`、`fields`、`passwordHistory` 的旧顶层 `data` 字段。当前仓库仍生成该字段，问题适用。

#### 修改内容

- `src/api/web.rs`：Custom Role 两条 CSS 规则改用 `:is(bit-dialog, [bit-dialog])`，并增加同时覆盖元素式和属性式 dialog 的回归测试。
- `src/db/models/cipher.rs`：删除仅用于构建旧 `data` 字段的克隆与拼装逻辑，不再序列化该字段；标准类型字段和顶层公共字段保持不变，并将既有序列化测试更新为明确断言 `data` 不存在。

#### 验证情况

- `cargo +1.97.0 test --all-targets`：58 passed、0 failed。
- `cargo +1.97.0 clippy --all-targets -- -D warnings`：通过。
- `cargo +1.97.0 fmt --all -- --check`：通过。
- `node --test tests/*.test.mjs`：20 passed、0 failed。
- `worker-build --release`：通过。
- `git diff --check`：通过，仅显示工作树 LF 将来可能转换为 CRLF 的提示。
- 未执行远程 Cloudflare 部署或真实 Web/Desktop/Mobile 客户端端到端验证。

#### 遗留事项

- 无本次任务的阻塞遗留项；属性式 dialog 的实际 UI 行为仍可在下一次真实 Web Vault 客户端回归中一并确认。

### 2026-08-04：按 Vaultwarden 结构重组源码

#### 用户需求

将 `agent/organization-management-migration` 分支的源码目录尽量对齐 Vaultwarden，并把 Workers、Webhook、Telegram 等项目特有实现隔离到额外文件中，降低后续上游同步成本。

#### 修改内容

- `src/handlers` 重组为 `src/api/core`，identity、icons、实时通知、Web 资源及 Axum 路由装配归入 `src/api`。
- `src/db.rs`、`src/models` 和两步验证持久化模块重组为 `src/db/mod.rs` 与 `src/db/models`。
- Attachment、Event、Collection、Group、OrgPolicy 和两步验证持久化逻辑归入 Vaultwarden 同名模型文件。
- Webhook、Telegram、企业微信和 outbox 归入 `src/extensions/notify`。
- Durable Object、R2、后台任务、日志及 D1 密钥管理归入 `src/worker_runtime`。
- 结构映射、平台边界和有意保留的 Axum 差异记录在 `.compat-reports/vaultwarden-structure-alignment.md`。

#### 验证情况

- `cargo check --target wasm32-unknown-unknown`：通过。
- `cargo test --lib`：67 passed、0 failed。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `cargo fmt --all -- --check` 与 `git diff --check`：通过。
- `node --test tests/*.test.mjs`：21 passed、0 failed。
- 未提交、未推送，也未部署 Worker 或修改 Cloudflare 资源。

## 待处理事项

- [x] 修复 `prelogin` 邮箱规范化、Email 2FA 未认证触发、密码提示账号枚举和附件/Send 全量内存缓冲。
- [x] 修复设备 `clear-token`/不存在设备读取语义、profile/verify-password 响应、根 `/alive` 与通知 keepalive。
- [ ] 将本次本地 HTTP/D1/R2/DO 验收脚本整理为仓库内可重复运行的自动化集成测试；目前新增的持久测试主要是 Rust 合约测试。
- [ ] 使用当前 Web/Desktop/Android/iOS/CLI 和至少一个 2025.5 之前的客户端做端到端矩阵；远程验证 D1、R2、DO 和大文件限制。
- [ ] 涉及生产行为时，按任务需要补充远程部署版本、D1/R2/DO 绑定和真实客户端验证。
- [ ] 可选：为密码学和随机数依赖的下一主版本补齐端到端兼容测试后再单独升级。

## 最近一次任务摘要

- 任务：将组织管理迁移分支的文件结构对齐 Vaultwarden，并隔离 Workers 与通知扩展。
- 结论：核心 API 与模型已归入 `src/api`、`src/db/models`；平台和通知特性已归入 `src/worker_runtime`、`src/extensions`。Axum 路由装配及较细的 handler 拆分作为有意差异保留。
- 验证结果：Wasm 编译、严格 Clippy、67 项 Rust 测试、fmt、21 项 Node 测试和 diff check 全部通过。
