# LibrarySquirrel 盲转中继 · 线协议与部署契约（PROTOCOL）

> 本文档是中继的**对外唯一契约**：主仓库（分享方/收件人客户端）按本文独立实现对接，两仓库互不依赖代码。
> 位置模型：中继是**盲转管道**——只搬运分享方与收件人之间端到端加密的密文字节，不存储、不解密、不感知内容；
> **加密密钥从不经过中继**（密钥走分享链接分发，见「安全模型」）。
> 实现版本：协议 version 1。

## 1. 总览

- **单端口**：线协议与 HTTP（落地页/举报/管理）共用一个 TCP 端口，按连接前 2 字节嗅探分流——`"LS"`（0x4C 0x53）进入线协议，其余按 HTTP 处理。浏览器/HTTP 客户端无感知。
- **角色**：
  - **分享方（sharer）**：主动向外连中继，注册分享会话（register）或重连（bind），该连接成为**出站隧道**，一条隧道复用 N 条并发虚拟流（frp 模式）。
  - **收件人（recipient）**：拨号（dial）某个 token，**每条收件人 TCP 连接 = 隧道内一条虚拟流**。
- **流（stream）**：不透明双向字节管道。流内承载的应用层协议（manifest 拉取、文件分块等）由客户端端到端加密，中继不可见也不路由。
- **TLS**：代码不内置。部署时经 TLS 终结的反向代理暴露（见「部署」）；TLS 终结后中继看到的仍是明文帧，单口嗅探不受影响。

## 2. 帧格式

所有多字节整数均为**大端**。

```
+---------+---------+--------+----------+--------+-----------------+
| magic   | version | type   | streamID | length | payload         |
| 2 字节  | 1 字节  | 1 字节 | 4 字节   | 4 字节 | length 字节     |
+---------+---------+--------+----------+--------+-----------------+
```

| 字段      | 值/约束                                                     |
|-----------|-------------------------------------------------------------|
| magic     | 固定 `"LS"`（0x4C 0x53），兼作单口嗅探前缀                    |
| version   | 固定 `1`                                                    |
| type      | 帧类型（见下表），**封闭白名单**，未知类型即断连               |
| streamID  | 控制帧必须为 0；流帧必须非 0；语义不符即断连                   |
| length    | payload 字节数，超过中继配置 `maxPayload`（默认 32768）即断连 |

帧头共 12 字节。单帧单次写入，帧在 TCP 流上不与其他帧交织。

### 帧类型

| type | 名称          | 方向                  | streamID | payload           |
|------|---------------|-----------------------|----------|-------------------|
| 0x01 | HELLO         | 客户端 → 中继          | 0        | JSON（见 §3）      |
| 0x02 | WELCOME       | 中继 → 客户端          | 0        | JSON（见 §4）      |
| 0x03 | ERROR         | 双向（发送后断连）      | 0        | JSON `{code,message}` |
| 0x04 | STREAM_OPEN   | 中继 → 分享方          | 新分配 ID | 空                |
| 0x05 | STREAM_CLOSE  | 双向                  | 目标流    | 空                |
| 0x06 | DATA          | 双向                  | 目标流    | 不透明密文字节     |
| 0x07 | PING          | 双向                  | 0        | 空（原样回显到 PONG） |
| 0x08 | PONG          | 双向                  | 0        | 回显 PING 的 payload |
| 0x09 | REVOKE        | 分享方 → 中继（仅隧道）| 0        | 空                |
| 0x0A | RESULT        | 中继 → 分享方          | 0        | JSON `{ok,action}` |

**方向约束**（违反即断连）：客户端不得发送 STREAM_OPEN / WELCOME / RESULT；HELLO 只能是连接首帧。

## 3. HELLO 载荷

JSON、UTF-8，上限 `maxHelloBytes`（默认 4096）。**字段集封闭**：任何未知字段（包括但不限于 `path`、`key`）一律 `malformed` 拒绝——协议面不存在路径访问与密钥交换通道。

```jsonc
{
  "role": "sharer" | "recipient",
  "action": "register" | "bind",        // 仅 sharer；recipient 省略
  "token": "…",                          // bind 与 recipient 必填；register 省略（由中继生成）
  "instanceId": "…",                     // 设备绑定实例 ID，客户端自报；[A-Za-z0-9-]{8,128}
  "passwordHash": "…",                   // 可选；hex(sha256(访问密码))，64 位小写 hex；
                                         // 明文密码永不在线路上出现
  "expireSeconds": 604800,               // 仅 register：省略=中继默认(7天)；0=无限期；>0=自定义秒数
  "meta": {                              // 仅 register：落地页文字元数据（无任何图像字段）
    "title": "…",                        // ≤200 字符、无控制字符
    "workCount": 3,                      // 0..1e9
    "source": "…",                       // ≤100 字符（来源站点，落地页强制展示）
    "worksName": ["…", "…"]              // 可选：各作品名明文，顺序对齐分享清单；≤1000 条、
                                         // 每条 ≤200 字符、无控制字符；空名作品由分享方以「作品 {ID}」占位。
                                         // 仅 register 上传（明文上传=离开 E2E 加密域，中继可读）；
                                         // bind 复原不携带（中继侧已存）；无作品名时（旧分享方/空分享）键不出现
  },
  "candidateAddrs": ["…"]                // 仅 register：V2 直连候选地址（预留位，本期仅存储不消费）
                                         // ≤8 条，每条 ≤253 可打印 ASCII
}
```

### 3.1 分享方 register（注册分享会话）

连接 → 发 HELLO（role=sharer, action=register）→ 收 WELCOME（含新 token）→ 连接转为隧道。
约束：中继侧限流（每 IP 每小时 `registerPerIPPerHour`=5、全局每小时 60）、活跃会话数上限 `maxSessions`=1000、封禁名单（实例/IP）。
被拒时收 ERROR 后断连。

### 3.2 分享方 bind（断线重连）

连接 → 发 HELLO（role=sharer, action=bind, token=…）→ 收 WELCOME → 连接替换旧隧道（旧隧道在途流全部终止）。
凭 token 即可重绑（token 即持有凭证）；会话已撤销/过期/流量受限时拒绝。

### 3.3 收件人 dial（拨号拉取）

连接 → 发 HELLO（role=recipient, token=…, instanceId=…, passwordHash=…）：
- 通过 → 收 WELCOME（空载荷）→ 该连接即一条虚拟流，双向 DATA 传输密文；
- 拒绝 → 收 ERROR 后断连。

## 4. WELCOME / RESULT / ERROR

```jsonc
// WELCOME（register 应答）
{ "token": "22 字符 base64url", "expiresAt": 1756000000000 }  // expiresAt unix 毫秒，0=无限期
// WELCOME（bind 应答）
{ "expiresAt": 1756000000000 }
// WELCOME（dial 应答）
{}

// RESULT（REVOKE 的应答）
{ "ok": true, "action": "revoke" }
```

### ERROR code 枚举

| code          | 语义                                   | 典型场景                  |
|---------------|----------------------------------------|---------------------------|
| malformed     | 输入非法（帧/JSON/字段/超长/未知字段）  | 一切输入校验失败           |
| not_found     | token 不存在                           | 拨号/重绑未知 token        |
| expired       | 会话已过有效期（kill-switch 已触发）    | 拨号/重绑过期会话          |
| revoked       | 会话已被撤销（分享方/举报/管理端）      | 拨号/重绑已撤销会话        |
| bad_password  | 访问密码缺失或错误                      | 拨号密码校验失败           |
| banned        | 实例或 IP 在封禁名单                    | 注册/拨号/重绑             |
| offline       | 分享方隧道不在线                        | 拨号时无活动隧道           |
| limit         | 并发/流量/会话数超限                    | 超并发流、流量上限、会话上限 |
| rate_limited  | 操作频率超限                            | 注册/拨号/举报风暴          |
| server_error  | 中继内部错误                            | 极端情况                   |

## 5. 流语义（多路复用）

- **流 ID 由中继分配**（隧道内单调递增，从 1 开始），经 STREAM_OPEN 通知分享方。分享方不得使用未分配过的流 ID（迟到帧会被静默丢弃，不影响隧道）。
- **收件人连接上唯一流固定 streamID=1**。
- **半关闭**：收件人发 STREAM_CLOSE 表示「我发完了」，中继转发给分享方；分享方仍可回发 DATA + STREAM_CLOSE 结束流（请求-响应模式的正常收尾）。分享方发 STREAM_CLOSE 时中继把剩余数据排空后送达收件人并关闭连接。
- **背压与慢消费者**：中继每流向收件人方向缓冲 128 帧（`32KB × 128 = 4MB`）；缓冲满即断流（收件人连接被关闭）。客户端应实现**消费确认或分块限速**（如每发 N 块等一次响应），避免瞬时突发超过缓冲。
- **保活**：隧道由中继按 `tunnelKeepaliveSec`（默认 30s）发 PING，分享方必须回 PONG；`tunnelKeepaliveTimeoutSec`（默认 75s）内无任何入帧即判定隧道死亡。收件人连接空闲 `recipientIdleTimeoutSec`（默认 600s）即断开；收件人也可发 PING 保活。
- **撤销/过期/封禁/流量超限**：中继立即关闭隧道与全部在途收件人连接（处置即时生效），后续拨号被拒。

## 6. HTTP 面

| 方法/路径                 | 说明                                                              |
|---------------------------|-------------------------------------------------------------------|
| `GET /s/{token}`          | 落地页：仅文字元数据（标题/作品数/来源/作品名列表/时间/有效期）+「打开应用」+「举报」+ 合规文案（服务条款/免责声明、隐私声明、举报与处置流程、AGPL 源码获取）；无任何图像；分享方离线仍可访问；未知 token 返回 404 页 |
| `POST /s/{token}/report`  | 举报：**立即撤销该会话**（即时生效）；同实例累计 `autoBanReportThreshold`（默认 3）次被举报自动封禁该实例；限流每 IP 每小时 `reportPerIPPerHour`=10（超限 429） |
| `GET /healthz`            | 健康检查                                                          |
| `POST /admin/kill`        | 管理端终止会话 `{"token":"…"}`                                     |
| `POST /admin/ban`         | 管理端封禁 `{"instanceId":"…"}` 或 `{"ip":"…"}`（级联撤销其活跃会话） |
| `POST /admin/unban`       | 管理端解封                                                        |
| `GET /admin/sessions`     | 会话清单（状态/在线/并发/流量/举报数/候选地址）                    |
| `GET /admin/bans`         | 封禁名单                                                          |

管理 API 鉴权：请求头 `X-Admin-Token` 与配置 `adminToken` 常量时间比对；**未配置 adminToken 时整个 /admin 返回 404（禁用）**；令牌错误返回 401。

落地页深链格式：`library-squirrel://share/{relay}/{token}`，其中 `{relay}` 为中继对外地址（配置 `publicAddr` 优先，否则按请求 Host 推导）。

**`{relay}` 地址语义**（客户端侧统一判据，落地页链接 `https://{relay}/s/{token}` 与深链共用）：`{relay}` 为去 scheme 的 `host[:port]` authority，按书写形态推断拨号传输与端口——公网字面量与显式 `https://` 前缀即 **TLS**（缺省端口 443）、显式 `http://` 前缀为明文逃生口（缺省端口 9527）、回环/RFC1918 私网/`localhost` 字面量缺省明文 9527（本机与局域网开发豁免，显式 `https://` 可覆盖）、`tcp://` 前缀不支持（报错）。显式前缀总是覆盖地址类别缺省；豁免为纯字面量匹配、不做 DNS 解析，裸公网 IP **不**豁免——服务端证书须含该 IP 的 SAN，无域名的中继在新语义下实际不可达（以文案引导配域名）。**深链与落地页链接恒表现为 https 形态**（`{relay}` 不带 scheme），收件侧推断不存在「`http://` 明文」分支：公开可达的中继必须自配 TLS 门面（见第 10 节），落地页与 App 拨号同走 443。

## 7. 会话与访问控制模型

- **token**：中继生成，16 字节 crypto/rand → base64url 无填充，22 字符（`[A-Za-z0-9_-]`），128 bit 熵，不可猜测；URL 安全。token 即访问凭证（含隧道重绑权）。
- **有效期**：注册时省略 → `defaultExpireSeconds`（默认 7 天）；`expireSeconds: 0` → 无限期；`>0` → 自定义（超过 `maxExpireSeconds` 截断，0=不设上限）。语义是**分享方显式失效控制**（到点中继显式拒绝并断开在途流，kill-switch 定时器扫描 + 拨号/落地页惰性判定），**非可用性承诺**——分享方离线链接即断。
- **撤销**：分享方 REVOKE 帧 / 落地页举报 / 管理端 kill，三者等价——会话立即终止、在途流断开、终态不可逆（重绑亦被拒）。
- **流量上限**：`maxSessionTrafficBytes`（默认 64 GiB，0=不限）按双向 DATA 负载累计，超限即断流并拒绝后续拨号（`limit`）；计数在内存中，中继重启后重新累计。
- **并发上限**：单会话并发流 `maxStreamsPerSession`（默认 8）、全局并发流 `maxGlobalStreams`（默认 512）、全局连接数 `maxConns`（默认 2048，线协议+HTTP 合计）、活跃会话数 `maxSessions`（默认 1000）。
- **候选地址（V2 预留）**：`candidateAddrs` 注册时登记、随会话持久化，本期协议不消费——V2 直连升级只翻偏好序，不改本契约其他部分。

## 8. 溯源与合规

- **溯源日志**（JSONL，按日切文件于 `traceDir`，默认留存 183 天——超期文件由启动清理与每小时定时清理删除，落地页隐私声明展示实际配置值）：`{ts, event, token, instanceId, ip, detail}`。事件含 register/bind/dial/dial_rejected/revoke/report/expire/ban/unban/traffic_limited/tunnel_down。**永不记录内容字节**。
- **封禁**：按实例 ID 与 IP 两维；落地页举报累计达阈值自动封禁实例；管理端可手动封禁/解封（即时生效，级联撤销活跃会话）。
- **终态会话保留**：撤销/过期会话记录不删除（处置与溯源连续性），状态文件随会话增长属预期（见「遗留」）。

## 9. 配置参考

配置文件：`-config relay.json`（JSON；文件或任意键缺省用默认值）。键与默认值：

```jsonc
{
  "listenAddr": "0.0.0.0:9527",        // 监听地址（线协议+HTTP 单口）
  "publicAddr": "",                    // 对外地址（深链用）；空=按请求 Host
  "downloadUrl": "",                   // 落地页兜底下载链接
  "adminToken": "",                    // 管理令牌；空=禁用管理 API
  "logLevel": "info",
  "stateFile": "state.json",           // 会话+封禁状态持久化（原子写）
  "traceDir": "log",                   // 溯源日志目录
  "traceRetentionDays": 183,
  "defaultExpireSeconds": 604800,      // 7 天
  "maxExpireSeconds": 0,               // 0=不限
  "maxSessions": 1000,
  "maxStreamsPerSession": 8,
  "maxGlobalStreams": 512,
  "maxSessionTrafficBytes": 68719476736, // 64 GiB；0=不限
  "maxConns": 2048,
  "maxPayload": 32768,                 // 单帧负载上限
  "maxHelloBytes": 4096,
  "handshakeTimeoutSec": 15,
  "writeTimeoutSec": 30,
  "tunnelKeepaliveSec": 30,
  "tunnelKeepaliveTimeoutSec": 75,
  "recipientIdleTimeoutSec": 600,
  "sniffTimeoutSec": 10,
  "sweepIntervalSec": 10,              // 过期扫描间隔
  "registerPerIPPerHour": 5,
  "registerGlobalPerHour": 60,
  "dialPerIPPerMinute": 60,
  "reportPerIPPerHour": 10,
  "autoBanReportThreshold": 3,
  "trustProxyHeaders": false           // 经反代部署取 X-Forwarded-For 时开启
}
```

## 10. 部署

- 直接运行：`library-squirrel-relay -config relay.json`（Windows/Linux 均可，零第三方依赖）。
- **TLS**：代码不内置，由反向代理终结。HTTP 部分可走常规 L7 反代；线协议是原始 TCP，需 **L4 直通或 TLS 终结的 TCP 代理**（nginx `stream` 模块、HAProxy、stunnel 均可）。TLS 终结后单口嗅探不受影响。
- **状态文件损坏**不阻断启动：损坏文件改名 `*.corrupt-<ts>` 旁路保存后从空状态运行。
- 中继重启：会话与封禁状态从 `stateFile` 恢复；隧道不保留（分享方需 bind 重连）；流量计数清零。

## 11. 客户端实现指引（阶段3 对接要点）

1. 分享方：一条长连接（register/bind），读循环分发 STREAM_OPEN/DATA/STREAM_CLOSE/PING；**串行化连接写**（帧原子性）；对每条流实现流内应用协议（建议：`nonce(12) || AES-256-GCM(明文)`，密钥来自分享链接、不经中继）。
2. 收件人：每次拉取一条连接（= 一条流）；请求发送完发 STREAM_CLOSE 半关闭，继续读响应至对端 STREAM_CLOSE。
3. 分块与背压：单帧 ≤ `maxPayload`；发 N 块等一次确认，或按接收窗口限速，避免撞 128 帧缓冲断流策略。
4. 保活：分享方必须应答 PING（PONG）；长时间静默的收件人连接自行 PING 或接受空闲断开重拨。
5. 重试语义：`offline` 可重试（等待分享方 bind）；`revoked`/`expired`/`banned` 为终态，不要重试；`rate_limited`/`limit` 退避后重试。
6. **TLS 拨号**：App 与中继的线协议连接（隧道、注册、收件人拨号拉取）**缺省走 TLS**——把中继地址按第 6 节地址语义解析为「拨号地址 + 是否 TLS」两个显式字段（不把传输形态再编码进地址字符串），TLS 路径以 `tls.Dialer` 握手（**SNI 取地址 host**、系统根证书严格校验、**不提供跳过证书校验选项**，连接与握手全程共用既有拨号超时预算），明文路径保持 TCP 直连、行为与改造前一致；帧协议与传输层正交，中继进程不感知 TLS（TLS 终结在门面，见第 10 节）。缺省端口：TLS 443、明文 9527（显式端口覆盖缺省）。TLS 握手失败（证书不受信任/域名不匹配）须报**可区分于「连接被拒」的独立文案**，引导用户核对证书或改用域名；公网明文中继误配（裸域名/裸 IP 缺省即 TLS）时文案引导「明文中继请加 `http://` 前缀」。

## 12. 安全模型（「盲」的边界）

- 中继**物理上无法读取内容**：全部流内容为端到端密文；中继源码不引入任何分组密码/解密能力（有结构性测试锚定：`TestRelaySourceHasNoDecryptCapability`）。
- **密钥不经中继**：HELLO 字段集封闭（未知字段即拒），协议不存在密钥交换通道；密钥走分享链接分发（链接即密钥，泄露=内容泄露，属已登记的产品级风险决策）。
- **无路径面**：隧道不暴露任何路径/URL 路由——流是不透明字节管道，不存在路径穿越攻击面；帧类型与 HELLO 字段双封闭白名单。
- **资源耗尽防护**：全局连接/会话/流三级并发上限 + 单会话流量上限 + 注册/拨号/举报三维限流 + 慢消费者断流策略。
- 访问密码（可选）以 sha256 hex 在 HELLO 中携带并常量时间比较，明文密码永不在线路上出现。
