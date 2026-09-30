# 证书生命周期实验平台

本地 PKI 教学实验：完整覆盖 **签发 → 轮换 → 验证（含历史证据）**，
支持多条信任路径（根迁移交叉签发），验证时逐路径给出期限、用途、撤销资料等分项结论。

## 运行

```bash
# 1. 后端（Go 1.27）
cd backend
go run ./cmd/certlab -addr :8080 -data ./data -web ./web

# 2. 前端开发模式（可选，热更新）
cd frontend
npm install   # 已预装依赖时可跳过
npm run dev   # 自动把 /api 代理到 :8080
```

重新构建前端到 `backend/web/`：

```bash
cd frontend && npm run build
```

浏览器打开 http://localhost:8080 即可使用操作页面。

## 内置本地样例

| 叶子证书 | 场景 | 预期 |
| --- | --- | --- |
| `leaf-cross` | `int-mig` 同时被旧根直接签发、被新根**交叉签发** | 存在 2 条候选路径；页面标明实际采用哪一条 |
| `leaf-expired` | 中间 CA 已过期（每一级签名本身都正确） | **不通过**：不会因为某张证书签名正确就放行 |
| `leaf-nocrl` | 中间 CA 不发布 CRL（撤销资料缺失） | **不通过**：撤销资料检查失败 |

## 验证规则

每条候选路径独立检查，任一项失败则该路径无效；只有存在全部通过的路径时整体才通过：

1. **用途**：叶子证书 ExtKeyUsage 包含所请求的 serverAuth/clientAuth；
2. **签名**：逐级验签 + Go `x509.Verify` 完整链校验（根需自签名且为当前受信任锚点）；
3. **期限**：链上每张证书都在 NotBefore/NotAfter 内；
4. **撤销资料**：每个签发 CA 的 CRL 必须可获取、签名有效、未过期，且未列出链上证书序列号；CRL 每次验证实时生成，不使用缓存；
5. **信任**：只接受当前在信任列表中的根（迁移期可同时信任新旧根）。

## 证据留存

每次点击“重新验证”都会向 `backend/data/evidence.jsonl` **追加**一条不可变 JSON 记录
（含所有候选路径、分项检查结果、采用路径、备注与时间戳）。信任规则变化后复检会产生新记录，旧证据永不覆盖。

## HTTP API

- `GET /api/certs` 证书清单与当前受信任根
- `POST /api/roots` / `POST /api/intermediates`（支持 `crossSubjectId` 交叉签发）/ `POST /api/leaves`
- `POST /api/leaves/rotate` 轮换终端证书（旧证保留并标记 `supersededBy`）
- `POST /api/trust` 切换根信任；`POST /api/revoke` 撤销；`POST /api/crl` 切换 CRL 发布
- `POST /api/verify` 实时验证并追加证据；`GET /api/evidence` 历史证据；`GET /api/crl/{id}` 实时 CRL

## 测试

```bash
cd backend && go test ./...
```
