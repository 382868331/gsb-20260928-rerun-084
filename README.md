# 证书生命周期实验平台

本地的 X.509 证书签发、轮换、交叉签发与链验证实验平台。后端使用 Go 标准库
`crypto/x509` 真实生成 ECDSA P-256 证书与 CRL；页面为零依赖静态资源，直接由
Go 服务内嵌托管（不需要 Node 构建）。

## 运行

```bash
cd backend
go run ./cmd/certlab
# 打开 http://localhost:8080
```

服务启动时自动载入三组本地样例；页面上的“载入本地样例”可随时重置后重新载入。

## 验证规则

每次验证会枚举终端证书到自签根之间的全部候选密码学路径，并对每一条路径检查：

- 签名链完整且由 `x509.Certificate.Verify` 确认（单张证书签名正确不代表通过）；
- 链上每张证书的生效/失效期限；
- 终端证书 ExtKeyUsage 是否包含所选用途（serverAuth / clientAuth）；
- 末端必须是当前受信任的根锚点；
- 每个签发 CA 必须发布撤销资料；CRL 为实时生成，校验签名、时效与序列号。

结果会给出实际采用的路径；没有任何一条完整路径通过时整体失败，并列出各条候选
路径的失败原因。

## 证据留存

每次“重新验证”都会生成一条不可变证据记录（自增 evidenceId、检查时间、规则版本、
全部候选路径明细）。信任根变化或 CRL 发布状态变化会使 rulesVersion 递增；新验证
只追加记录，不覆盖旧证据，历史按时间倒序展示。

## 本地样例

| 终端证书 | 场景 | 预期 |
| --- | --- | --- |
| leaf-ok | rootA→intermediateX 与 rootB→crossX（交叉签发同一中间密钥）两条信任路径 | 两条路径均有效，显示实际采用路径 |
| leaf-rotated | 同一中间 CA 轮换出的新一代终端证书（新密钥） | 独立验证，旧证书保留 |
| leaf-expired | rootC→expired-im（中间证书有效期为 -1 年，已过期） | 失败：期限不满足，即使签名全部正确 |
| leaf-nocrl | rootD→silent-im，该 CA 停止发布 CRL（撤销资料缺失） | 失败：revocation data missing |
| leaf-revoked | 已撤销终端证书，序列号出现在实时 CRL 中 | 失败：证书已撤销 / CRL 列名 |

页面还可把 rootA 取消信任，演示根切换后 leaf-ok 自动改走 rootB→crossX 路径；
重新验证后历史中同时保留切换前、后两条证据。

## API 摘要

- GET /api/state：全部证书（不含私钥）、信任根、规则版本
- POST /api/roots、POST /api/intermediates（支持 crossSubjectId 交叉签发、负年数过期）
- POST /api/leaves、POST /api/leaves/rotate
- POST /api/certs/{id}/revoke、/trust、/crl
- GET /api/crl/{id}：实时生成的 DER CRL
- POST /api/verify：执行验证并追加证据
- GET /api/history：不可变验证证据（新到旧）
- POST /api/samples、POST /api/reset

## 测试

```bash
cd backend && go test ./...
```
