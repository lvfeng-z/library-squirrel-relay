# library-squirrel-relay

LibrarySquirrel 远程分享功能的**盲转中继**：零第三方依赖的 Go 单二进制服务，为分享方（App 即内容源，出站隧道穿透 CGNAT）与收件人之间转发**端到端加密**的数据流。中继不存储、也无法读取任何分享内容——只搬运密文帧并维护会话账目（token 访问控制、有效期、封禁/限流、溯源日志、落地页）。

- 线协议与部署契约：[PROTOCOL.md](PROTOCOL.md)（**契约冻结**）
- 许可：**AGPL-3.0**（见 [LICENSE](LICENSE)）——防第三方中继者闭源篡改（改日志/改加解密）；作者自营实例披露义务不额外（作者即源码持有者）
- 客户端仓库（GPL-3.0）：`../library-squirrel/`

## 构建与运行

```bash
go build ./...        # 编译
go test ./...         # 全量测试（含合规核验）
./library-squirrel-relay -config relay.json   # 运行；配置键与默认值见 PROTOCOL.md「配置参考」
```

TLS 由部署期反向代理终结（代码不内置，见 PROTOCOL.md「部署」）。

## 运营合规对照

对照《分享功能总体方案》第六节「合规机制清单」逐条标注落地位置（文件 / 测试锚点）：

| # | 机制 | 落地位置 | 测试锚点 |
|---|------|----------|----------|
| 1 | 端到端加密（中继不可读 → 无「明知」） | 全仓库结构性无解密能力（`access.go` 头注：不引入任何分组密码/解密包）；密钥只存在于分享双方客户端 | `TestRelaySourceHasNoDecryptCapability`（access_test.go，源码扫描）；`TestE2EBlindnessHardAcceptance`（relay_e2e_test.go，录制代理逐字节断言：转发字节==密文 / 线路无明文 / 密钥不进中继） |
| 2 | 加密链接 + 可选密码/有效期 | `access.go`（token=16 字节 crypto/rand→base64url，128 bit 熵；密码常量时间比较）；`session.go` `resolveExpireMS`（省略=中继默认 30 天、`expireSeconds`=0/负数即拒 `invalid_expire`、超 `maxExpireSeconds` 截断——**无限期已停用，新会话恒有到期时刻**）、惰性过期 + 定时扫描 kill-switch；`config.go` `validate`（`defaultExpireSeconds` 须为正数，0/负数拒绝启动） | `TestTokenUnguessable`、`TestPasswordProtection`、`TestExpiryKillSwitch`、`TestConfigRejectsNonPositiveDefaultExpire`（access_test.go） |
| 3 | 会话级溯源日志（定位分享方，配合举报/下架/执法） | `trace.go`（JSONL 按日切文件，字段集 `{ts, event, token, instanceId, ip, detail}`，永不记内容字节；留存期清理） | `TestTraceLogRecordsFactsNotContent`（access_test.go）；`TestTraceLogFieldSetExcludesContent`、`TestTraceRetentionCleanupUnit`、`TestTraceRetentionEnforcedViaSweep`（compliance_test.go） |
| 4 | 落地页强制展示来源 | `preview.go` `serveLanding` + `web/index.html`（标题/作品数/来源/作品名列表/时间/有效期，仅文字元数据、无任何图像，html/template 转义防注入） | `TestLandingPageServesTextMetadataOnly`、`TestLandingPageEscapesMetadata`（preview_test.go） |
| 5 | 举报 + 快速撤销 + 快速精准处置 | `relay.go` `reportSession`（举报即撤销；同实例达 `autoBanReportThreshold` 自动封禁并级联撤销其全部会话）；`preview.go` 管理端 `adminKill`/`adminBan`（按实例或 IP 精准封禁）/`adminUnban` | `TestReportAutoBan`（举报→撤销→实例封禁链路端到端）、`TestAdminKillSession`、`TestAdminBanAndKillByIP`、`TestRevokeKillsInFlightStreams`（access_test.go） |
| 6 | 全库分享禁止 + 规模上限 + 会话日志留存期 | 中继侧：规模与滥用面上限（`config.go`：maxSessions/maxStreamsPerSession/maxGlobalStreams/maxSessionTrafficBytes/maxConns + 注册/拨号/举报限流）；留存期 `traceRetentionDays`（默认 183 天 ≈ 6 个月，启动 + 每小时定时清理，落地页展示实际值）。**会话账目侧同有留存边界**：终态（撤销/过期）会话行自 `endedAt` 起保留 30 天后由定时扫描剪枝并落盘（`session.go` `sessionRetention`），状态文件不随历史会话无限增长。**全库分享禁止是分享方客户端约束**（主仓库阶段3 分享入口仅单作品/作品集/多选）——盲转中继协议上无从感知「库」的存在，以规模上限兜底 | `TestRegisterRateLimit`、`TestStreamConcurrencyLimit`、`TestTrafficLimit`（access_test.go）；留存期测试同 #3；会话剪枝 `TestSweepPrunesTerminalRows`（access_test.go） |
| 7 | ToS/免责声明 | `web/index.html`「服务条款与免责声明」（服务性质=盲转管道/不存储不审查/侵权违法举报即撤/免责边界）+「隐私声明」（个人信息保护法口径：记录字段/用途/留存期限/删除请求渠道）+「举报与处置流程」；未知 token 的 404 页承载同一合规件 | `TestLandingPageComplianceCopy`（compliance_test.go） |
| 8 | AGPL 披露义务 | `LICENSE`（AGPL-3.0 官方全文）；落地页「源码获取（AGPL-3.0）」节（源码仓库链接，AGPL 第 13 条对外呈现） | 同 #7（源码链接文案断言） |
| 9 | 中继运营合规（ICP 备案/落地页责任） | **部署期人工事项**，见下表 | —（非代码交付） |
| 10 | 分享方本机防护（风险8） | 客户端侧归主仓库阶段3/4（隧道协议路径白名单、与本地服务隔离）；**中继对应面**：恶意输入拒绝（`protocol.go` 帧校验 + HTTP 面路径安全）与资源耗尽防护（限流 + 各上限） | `TestMalformedFramesRejected`、`TestHTTPPathSafety`（protocol_malformed_test.go）；限流测试同 #6 |

## 部署期人工事项（非代码交付）

正式运营官方中继前由运营者完成（见方案第六节「运营落地清单」）：

| 事项 | 说明 |
|------|------|
| 域名注册 + ICP 备案 | 域名解析到境内主机必须备案（非经营性即可；经营性服务另需 ICP 经营许可证） |
| 网络安全等级保护 | 公共服务一般需定级备案并落实安全措施（常见二级） |
| 律师咨询 | 本文档是风险地图而非法律意见；个人 vs 公司主体运营的责任承担不同 |
| 落地页占位替换 | `web/index.html` 中隐私声明联系方式（`relay-privacy@example.com`）与源码仓库链接（`https://github.com/lvfeng-z/library-squirrel-relay`）为**占位**，正式运营前替换为实际值 |
| 配置核对 | `adminToken` 必设（否则整个管理 API 404 禁用）；经反代部署开启 `trustProxyHeaders`（否则来源 IP 取代理地址，封禁/限流失效）；`traceRetentionDays` 按运营需要设置（落地页隐私声明自动展示实际值，与 `state.json` 一同纳入运营数据管理）；`defaultExpireSeconds` 须为正数（无限期已停用，0/负数拒绝启动），`maxExpireSeconds`=0 表示自定义有效期不设上限 |
