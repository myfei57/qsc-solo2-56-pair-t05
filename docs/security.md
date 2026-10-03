# 指令防伪（命令签名与验签）

门控服务原来"只认内容不认来源"：任何能访问控制台接口的报文都会被执行。本方案
给每条外部开关指令加上**对称签名（HMAC-SHA256/HS256）**，门控在执行前完成
验签、防重放、有效期与授权范围校验，并把密钥做成可轮换、把每条指令的验签结论
落进审计。纯标准库实现，不引入运行期第三方依赖。

## 1. 信任边界与策略取舍

- **外部网络指令（控制台 POST `/api/...`）全部走守卫**：无有效签名一律不执行。
- **本地可信调用（CLI、内部控制周期 `cycle()`、装配/恢复）保持直调**，不经
  网络，信任边界画在"外部报文"这一层。GET 查询接口只读，不验签。
- **验签失败默认丢弃并告警（`enforce`）**。理由：轨旁安全系统必须 fail-closed，
  挂起等待人工会让值班员成为吞吐瓶颈，且把不可信报文留在执行路径上本身是风险。
  失败报文不会无声消失——它连同判定码一起进审计告警，连续失败立安全告警牌。
- **可选 `hold` 模式**：失败指令进入隔离区留证，但**永远不会被"批准执行"**；
  值班员核查后只能选择"确认丢弃"或"我用自己的新签名重发"（`reissued`）。
- **`observe` 模式**只记录不拦截，仅供上线灰度期与旧上位机对账，严禁长期使用；
  切回/切离都有审计事件。
- 安全告警牌只告警、**不拦截合法签名指令**，避免攻击者用失败流量制造 DoS。

## 2. 报文信封

```json
{
  "kid": "key-0002",
  "alg": "HS256",
  "nonce": "13e30b63dbf36e1a52a98cca1d719308",
  "iat": 1790936855.45,
  "exp": 1790936975.45,
  "action": "/api/arrive",
  "unit": "line1",
  "body": {"train_id": "T01", "station_id": "ST1", "position_m": 0},
  "sig": "198c2882ff51d4f5..."
}
```

签名串是除 `sig` 外字段按固定键序的紧凑 JSON（`sort_keys`、分隔符 `,`/`:`、
不转义非 ASCII）的 UTF-8 字节，`sig = hex(HMAC_SHA256(secret, 签名串))`。

绑定关系：

- `action` 必须等于实际投递路径（一条指令只能打它被授权的那个接口）；
- `unit` 必须等于本运行单元（防跨单元/跨线重放）；
- `iat/exp` 限定生效窗口（默认 TTL 120s，收发时钟偏差容限 30s）；
- `nonce` 128 位随机，一条指令一个，全局唯一。

签发侧参考实现：`psdline.security.signer.Signer` / `psdline sign`。

## 3. 验签九步（判定码稳定，审计按码统计）

| # | 步骤 | 失败码 |
|---|------|--------|
| 1 | 信封结构/字段/算法/签名格式 | `malformed`（含 `bad_algorithm`/`bad_timestamp`/`malformed_signature`/`malformed_body`） |
| 2 | `kid` 在密钥环中存在 | `unknown_kid` |
| 3 | 密钥未吊销/未退役 | `key_revoked` / `key_retired` |
| 4 | `iat` 在偏差窗口内、报文未陈旧 | `bad_timestamp` |
| 5 | 当前时间未过 `exp`，TTL 不超限 | `expired` / `bad_timestamp` |
| 6 | `unit` 与本单元一致 | `bad_unit` |
| 7 | `action` 与实际路径一致 | `action_mismatch` |
| 8 | HMAC 签名匹配（`hmac.compare_digest`） | `bad_signature` |
| 9 | `nonce` 未被消费 | `replay` |

## 4. 密钥轮换

密钥四态（`psdline/security/keyring.py`）：

- `active`：当前签名钥，全局唯一，也参与验签；
- `grace`：旧 active，**只验签不签名**，带 `retire_at`；
- `retired`：并存期结束，密钥材料从磁盘擦除，仅留指纹墓碑供审计追溯；
- `revoked`：疑似泄露立即吊销，擦除材料，验签一律拒绝。

**并存期默认 24h（`security.rotate_overlap_s`，可配置）**：轮换 = 建新 active +
旧 active 转 grace，期间新旧密钥签的指令都能验；并存期到了惰性退役（任何一次
验签/查询会触发），也可用 `keys retire` 显式退役。任意时刻可验签密钥最多两把。

密钥文件独立目录（`security.secrets_root`，默认 `var/secrets`，建议挂 tmpfs 或
收紧权限），每把钥匙一个 JSON，创建即 `chmod 0600`；墓碑不含密钥。

## 5. 防重放与执行原子性

守卫（`psdline/security/guard.py`）在一把全局指令锁内串行处理：

```
取锁 → 验签 → nonce 落盘消费（fsync）→ 记 command_verified 审计
     → JsonStore 事务内执行 → 成功提交 / 异常逆序回滚 + command_rolled_back
```

- **nonce 先消费、后执行，且不参与事务回滚**：执行失败的指令也不能用原报文
  重发，必须由签发侧换新 nonce 重签——从根上断掉"失败即重试"造成的重放。
- nonce 台账是只追加 JSONL（`nonces-*.jsonl`），重启回放重建内存集合，掉电不
  丢判重；按 `nonce_retention_s`（默认 600s，不短于 TTL）滑动清理。
- `ThreadingHTTPServer` 的并发请求在同一把指令锁上排队；同一 nonce 并发只有
  一个能赢，其余得到 `replay`。

## 6. 部分失败回滚

- `JsonStore.transaction()` 在线程栈记录每次 `write/remove` 的事务前快照；
  异常时逆序原子恢复（新建文件删除、覆盖文件还原旧内容），支持嵌套。
- 只追加流水（审计、nonce 台账）按设计不回滚；遥测内存计数由平台的
  `_telemetry_checkpoint/_telemetry_restore` 恢复。
- 业务拒绝（`RailError`，如联锁条件不满足、配额不足）维持既有 400/409 语义，
  **不算部分失败、不回滚**；非预期异常才回滚并返回 500 `PartialFailure`。

## 7. 审计追溯

每条指令都有凭据 `auth_id`（`auth-xxxx`）：

- `command_verified`（含 kid/nonce/action/iat/exp/age/checks）、`command_executed`；
- 失败：`command_rejected`（alarm，带九步 `checks` 与 reason）；
- hold：`command_held`，处置 `hold_dismissed`/`hold_reissued`；
- 回滚：`command_rolled_back`（alarm，带错误类型）；
- 密钥：`key_rotated`/`key_revoked`/`keys_retired`、`security_mode_changed`。

执行作用域内的业务审计（`door_enqueue`、`arrive_complete` 等）自动带同一个
`auth_id`，可用以下方式重建一条指令的完整链路：

- API：`GET /api/audit/auth/{authID}`、`GET /api/audit/verdicts`；
- Python：`psdline.audit.by_auth(entries, auth_id)`。

门控队列里的每条 `DoorCommand` 也落了 `auth_id`，排队指令同样可回溯。

## 8. 运维操作（CLI）

```bash
# 首次布防（也可由服务首次启动按 security.bootstrap 自动生成）
psdline keys bootstrap --show-secret
psdline keys list                     # 只看 kid/状态/指纹，永不打印密钥
psdline keys rotate --show-secret     # 轮换，输出新钥与并存期截止时间
psdline keys retire                   # 显式退役到期旧钥
psdline keys revoke --kid key-0001    # 立即吊销

# 上位机/值班侧签发（输出可直接 POST 的信封 JSON）
psdline sign --action /api/arrive \
  --body '{"train_id":"T01","station_id":"ST1","position_m":0}'

curl -s http://127.0.0.1:8080/api/arrive \
  -H 'Content-Type: application/json' -d "$(psdline sign ...)"
```

管理类接口（轮换、吊销、改模式、清告警、处置隔离区）本身也必须带签名信封：
`POST /api/security/{rotate,revoke,retire,mode,reset-alarm}`、
`POST /api/quarantine/{dismiss,reissued}`；查询 `GET /api/security`、
`GET /api/quarantine`。

## 9. 配置（`config/psdline.json` 的 `security` 节）

| 键 | 默认 | 说明 |
|----|------|------|
| `mode` | `enforce` | `enforce` / `hold` / `observe` |
| `secrets_root` | `var/secrets` | 密钥目录（独立于状态目录，权限 0700/0600） |
| `rotate_overlap_s` | `86400` | 轮换后旧钥可验签的并存期 |
| `command_ttl_s` | `120` | 指令有效期 |
| `max_skew_s` | `30` | 收发时钟偏差容限 |
| `nonce_retention_s` | `600` | nonce 防重放保留窗口（不短于 TTL） |
| `bootstrap` | `true` | 首次启动无密钥时自动生成一把 active |
| `failure_alarm_threshold` | `5` | 连续验签失败立牌阈值 |

## 10. 上线步骤（建议）

1. 部署服务，`keys bootstrap` 生成首把钥，密钥通过带外渠道分发给各上位机/ATS；
2. 各上位机用统一的签发库（`Signer` 或同规范实现）签名，先在 `observe` 下
   对账一个短窗口，确认没有合法报文被判错；
3. 切 `enforce`（签名调用 `/api/security/mode`）；
4. 轮换：业务低峰 `keys rotate`，24h 并存期内逐步更新所有签发侧，`keys retire`
   收尾；确认告警平台订阅了总线 `security` 主题的 `security_alarm`。
