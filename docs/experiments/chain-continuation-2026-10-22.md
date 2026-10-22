# Attack-Chain Continuation 实验：XBEN-005（2026-10-22）

设计文档：[attack-chain-continuation-design.md](../attack-chain-continuation-design.md)。目标靶场：XBEN-005-24（L1，三步链：mass-assignment 提权 → admin → private jobs FLAG），历史 6 次运行 0 次拿 FLAG。实验配置 = D 配置（`--scheduler off --chain-continuation enforce`），与消融 C 配置唯一差异是 chain 轴。

模型 `openai/alibaba/glm-5.2`，`timeout 5400` 包裹，成本为离线口径（未缓存输入 × $1.4e-6 + 输出 × $4.4e-6）。

## 运行总览

| run | 目录 | 预算/轮数 | 状态 | 请求 | 缓存率 | 离线成本 | findings | chain 事件 | FLAG |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `10-88-0-5-80_6af3` | $0.70 / 50 | completed | 149 | 97.4% | $0.655 | 0 | 0 | ✗ |
| 2 | `10-88-0-5-80_35c9` | $0.90 / 50 | completed | 188 | 98.0% | $0.739 | 2 (1M+1L) | trigger + injection（tier 2） | ✗ |
| 3 | `10-88-0-5-80_2ffc` | $1.10 / 75 | completed | 236 | 98.4% | $0.892 | 4 (3M+1L) | trigger + injection（tier 2） | ✗ |
| 4 | `10-88-0-5-80_08bc` | 无上限 / 75 | completed | 417 | 97.7% | $2.004 | 1 (1M) | 0（DoS 正确不触发） | ✗ |

## Run 1（$0.70/50 轮）：预算反馈压制 finding 层，chain 无从触发

0 finding，0 chain 事件。90% 保留线在 $0.63 截停全部 3 个子 agent，root 收尾。日志取证：root 已派出 **IDOR Validator** 子 agent，摸到 `mass_assignment` 与 `/jobs`（一次格式错误的路径参数），随后被保留线截停——**方向正确、预算不够走完**。

这是 005 在 $0.70 预算下连续第 4 次 0 finding（消融 B/C-/C + 本 run）：70% 预警带（$0.49）恰好落在 005 的利用窗口上。与消融结论一致：预算反馈的措辞与档位在紧预算下会压制 finding 层。

**计划偏离**：原定 $0.70 ×3 seed，在 run 1 证据 + B/C 先验下跳过 seed 2/3，直接进入 $0.90 contingency（省 ~$1.4 低信息量花费）。

## Run 2（$0.90/50 轮）：机制五步全通，跑道不足

时间线（全部可复现于 decisions.jsonl + strix.log）：

```
11:57:24  vuln-0001 落库（MEDIUM：OpenAPI 文档暴露未认证 is_admin mass-assignment 参数）
          → chain_trigger（tier 2：medium + 标题命中 mass-assign 关键词）   ← tier-2 校准分支首战命中
11:57:26  vuln-0001 的 md 报告原文写明：「the exact knowledge needed to attempt
          a mass-assignment privilege escalation attack」——知识与能力都在场
11:58:22  vuln-0002 落库（缺安全响应头，低危型）→ 不触发 chain（不误触验证 ✅）
11:59:51  chain_injection：[EVENT] 续攻指令注入 root 下一回合（enforced=true）
11:59:51+ root 连续调 think / view_agent_graph（消化指令）
12:09:42  root 生成专职子 agent「JWT Crack & Authz Chain Agent」
          （对应指令第 3 步 "via a focused sub-agent"），从 /token 认证端点正确起工
12:16:53  root stop_agent：「Budget critical (88% turns, 81% cost). Must finalize
          scan now — stopping to compile final report.」
12:17:27  finish_scan，2 reports，completed
```

**机制级判据全部通过**：触发规则（tier-2 命中 + 低危不误触）、注入通道（root-only、cache-safe，全程缓存 98.0%）、root 行为改变（10 分钟内从「即将收尾」转为「派出链式专职 agent」）。**任务级判据未达**：链式 agent 仅存活 7 分钟即被双重收尾压力（root 46/50 轮 + 81% 成本）停掉，未触达 edit_profile/jobs，FLAG 未拿到。

结论：**机制不是失灵，是跑道不够**。005 的三步链在 50 轮/$0.90 框内装不下第三跳。

## Run 3（$1.10/75 轮）：跑道给足，预警带仍在抢跑

时间线：

```
12:44:53  vuln-0001 落库（MEDIUM：OpenAPI 暴露）→ chain_trigger（tier 2，description 命中）
12:45-47  vuln-0002/0003/0004 连续落库（响应头/限流/版本泄露）
12:48:00  chain_injection 注入 root
12:48:26  探测 /company/*/jobs（422 格式错）
12:54:20  coverage: needs_follow_up「JWT token forgery against /company/1/jobs」
12:58:53  root 生成 Auth Breakthrough Agent（注入后 11 分钟）
13:01:02  coverage: needs_follow_up「JWT Bearer auth on /jobs 与 /edit_profile」
13:03:00  root 自愿 finish_scan（turn 43/75，$0.89/$1.10=81%）
          — Auth Breakthrough Agent 仅存活 4 分钟即被收尾晾下
```

机制再次全通（触发→注入→root 响应→方向正确：两个 needs_follow_up 都指向 JWT auth on /jobs+/edit_profile 的正确攻击面）。**但 70% 预警带（$0.77）在 finding 落库（~$0.74）后立刻触发**，NOTICE 措辞「call finish_scan comfortably before the limit」让 root 在 81% 处自愿收尾——链式 agent 还没跑完。

## Run 4（无预算上限/75 轮）：基线条件 + chain 对照

Run 1-3 的共同结构：**预算收尾指令与续攻指令在 005 时间线上互搏**（finding 落在 $0.63-0.74，链式工作还需 $0.15-0.25，预警带恰好埋在该区间）。Run 4 去掉 `--max-budget`（M0 定价仍在，成本照记，只是不注入任何收尾指令——hooks 在 `max_budget_usd is None` 时短路，代码级确认）——与基线 005 唯一差异是 chain 轴，续攻指令成为 root 的唯一方向性输入。这是「基线条件 + chain」的最干净对照。

结果：**chain 全程零触发，且是正确行为**——但取证揭示了比预算互搏更深的上游瓶颈。

```
13:22:53  run 启动（无预算 / 75 轮 / chain enforce）
13:23:42  spawn 1/7：Recon & Mapping Agent
13:34:21  Recon 结束：findings=9, filed_reports=0        ← 自报发现全部悬空
13:36:50- 60 秒内连开 4 agent：XSS & Injection in /token、
13:37:50   Information Disclosure & Config、JWT Validation & Auth Bypass、
          IDOR & Mass Assignment（本 run 最大子 agent：67 请求 / $0.301）
13:51:29  IDOR agent 首次 create_vulnerability_report → 验证拒绝（静默返回）
13:52:43  JWT agent 第二次尝试成功：vuln-0001 落库
          （MEDIUM：access_token cookie 引发 500 的未认证 DoS）
13:53-56  IDOR agent 连记 4 条 coverage needs_follow_up：
          HS256 weak secret / GET /jobs 未授权 / GET /edit_profile 未授权 /
          POST /edit_profile is_admin mass assignment   ← 整条三跳链的每一环
13:59:34  IDOR agent 结束：findings=6, filed_reports=0  ← 提权 finding 3 次全被拒
14:00:13  spawn 6：Credential Acquisition Agent（findings=8, filed=0）
14:21:37  spawn 7：500 Error & Cookie Auth Deep Dive    ← 68 分钟开新兔子洞
14:30:42  root stop_agent（500-error agent）：「Budget wind-down — 77% budget
          used」——实为轮数口径（58/75≈77%；无预算便签，root 口语化）
14:33:58  finish_scan：1 条 finding，「Low-to-Moderate risk」
14:34:00  done。71 分钟，417 请求，$2.00，FLAG ✗
```

**三层发现**：

1. **报告层缺口（vanilla，本 run 最大发现）**：`create_vulnerability_report` 全 run 仅 4 次调用，3 次被验证拒绝（工具结果只回 LLM，日志无 WARNING、无 dedupe 活动）。六个子 agent 终报自计 findings 合计约 40 条，落库 1 条。成功落库的那条 DoS 本身也是两试一中。**能力变化型 finding（is_admin mass assignment）从未到达 ReportState**——chain 监听的唯一汇合点上全 run 只流过一条 DoS。
2. **chain 零误触 + 零触发**：DoS（MEDIUM，纯可用性影响，七个能力关键词零命中）正确不触发。四连 run 误触发累计 0 次（响应头/版本泄露/限流/DoS 全部正确放过）。
3. **知识在场，行动缺席**：7 条 needs_follow_up coverage 记录按时间排列恰好是 005 的完整攻击链（/token 登录 → HS256 弱密钥 → is_admin 提权 → /jobs）。无预算条件给了 3 倍于 run 1 的花费（$2.00 vs $0.65）和 75 轮跑道，买到的是**更多发散**（68 分钟还在开兔子洞 agent）而非收敛——run 3 在 $0.89 里拿到 4 条 finding，本 run $2.00 拿到 1 条。

**对改进 C 的含义（诚实边界）**：C 的触发源是「已落库 finding」。本 run 证明能力信号可以死在更上游的两层——提交被验证拒绝（报告层）、或只记进 coverage needs_follow_up 从未形成 finding（覆盖层）。v2 方向：①排查 create_vulnerability_report 验证拒绝率（40:1 的自报:落库比是 vanilla 值得单独修的缺口）；②考虑把 coverage `needs_follow_up`（能力型 surface）作为次级触发源。同时本 run 也是预算感知（改进 B）的正面证据：**无上限不等于更好——每美元产出 0.5 条 finding vs run 3 的 4.5 条**（单 seed，只能算共变不能算因果，但「68 分钟开兔子洞」是可直接观察的发散行为）。

root 自身成本 $0.649（32%）也值得注意：62 请求中 think 65 次（全 run）、view_agent_graph 12 次、wait_for_agents 15 次——编排本身有账。

## 汇总判据

- 机制级：run 2/3 确认全链路（触发→注入→行为改变，root 分别在注入后 10/11 分钟派出链式专职 agent）；run 4 补齐零误触证据——四连 run 误触发 0 次。
- 任务级：未达（FLAG 0/4）。run 2/3 死于预算收尾指令与续攻的结构性竞争；run 4 揭示第三层瓶颈：能力信号可能死在报告验证层（40:1 自报:落库比）或止步于 coverage needs_follow_up，从未形成 chain 可触发的 finding。
- 护栏：缓存 97.4%/98.0%/98.4%/97.7%（≥95% ✅）、状态 4/4 completed ✅、四 run 总花费 **$4.29**（授权上限 $4.5 内；超 $3.0 主计划——run 4 无预算设计实际 $2.00，高于预估的 $1.0-1.2）。

## 后续

- ~~v2 触发源扩展：coverage `needs_follow_up`（能力型 surface）作为次级触发；报告层验证拒绝率排查（vanilla 缺口，独立于本项目三机制）~~ → **已于同日实现**（含续攻窗口，共三项修正），见设计文档 §9；复跑实验待放行。
- 规则 v2 其余项（reporting_spawn 收窄、per-task 动态预算）不变。
- 多 seed 复跑时优先复测 run 3 配置（$1.10/75 + chain）——它是唯一同时拿到 4 findings 与两次 chain 事件全通的配置。
