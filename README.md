# 证书生命周期实验平台

一个完全自包含的实验平台：Go 后端在**本地实验区**内生成虚构的测试证书链并管理签发关系与版本，React 前端提供签发、轮换、撤销、交叉签发与路径验证页面。

> 本平台只使用运行时自行生成的密钥，**从不读取电脑上已有的任何密钥**；私钥仅以 0600 权限写入实验区 `private/` 目录，路径与内容都不会进入 API 响应或页面日志。

## 首轮实验链

首次启动时自动生成（仅一次，之后重开恢复同一实验）：

- `Lab Root Old`（旧根）与 `Lab Root New`（新根）—— 换根窗口
- `Lab Intermediate Alpha`：
  - v1 已过期（旧根签发），其下的 `legacy.lab.test` 只能走过期链
  - v2 当前有效，旧根签发；同时存在一张**交叉证书**，用新根对 v2 的同一公钥重新签名
- `api.lab.test`（serverAuth）、`device.lab.test`（clientAuth）—— 用途检查

## 验证语义

每次验证都枚举从终端证书到根的全部候选链，并分别给出结论：

- **用途**：`serverAuth` / `clientAuth` 的 ExtKeyUsage 必须匹配
- **有效期**：链上每张证书都检查 NotBefore / NotAfter
- **信任起点**：仅当链顶根在页面勾选的信任库中才可能通过
- **撤销**：实时读取落盘状态，撤销后立即失败，不依赖任何缓存结论
- **旧链 / 新链**：交叉签发使同一张终端证书在旧根或新根信任库下分别通过，页面按链标注 old chain / new chain

状态原子写入 `state.json`，保存重开后序列号、版本、撤销状态完全一致。

## 运行

后端：

```bash
cd backend
go run ./cmd/certlab
# 可选：CERTLAB_DIR=/path/to/experiment-area CERTLAB_ADDR=127.0.0.1:8787
```

前端（已通过 Vite 代理 `/api` 到后端）：

```bash
cd frontend
npm install   # 若 node_modules 不存在
npm run dev   # http://localhost:5173
```

测试与构建：

```bash
cd backend && go test ./...
cd frontend && npx tsc --noEmit && npx vite build
```

## API

- `GET /api/state` 实体、版本、根列表
- `POST /api/bootstrap` 首轮链引导（幂等）
- `POST /api/issue` 签发根 / 中间 / 终端；对同名主体再次签发即轮换出新版本
- `POST /api/cross-sign` 对中间证书版本生成交叉证书
- `POST /api/revoke` 撤销版本并立即持久化
- `POST /api/verify` 指定终端证书、用途、信任根集合（及评估时间偏移）验证
- `POST /api/reset` 清空实验区并重新引导

## 后续

批量签发/轮换策略（批量窗口、灰度、自动交叉签发等）留待下一轮在现有版本模型上扩展。
