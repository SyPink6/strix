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

---

# v2 复跑 + 深度取证（2026-10-22 下午，授权 2 run）

用户放行 2 个复跑 run（run 3 配置：`--max-turns 75 --max-budget 1.10 --chain-continuation enforce`）。

| run | 目录 | 靶场状态 | 状态 | 时长 | 请求 | 缓存率 | 离线成本 | FLAG |
|---|---|---|---|---|---|---|---|---|
| v2-1 | `10-88-0-5-80_6039` | **被污染**（见下） | completed | 36 min | 213 | 97.5% | $1.02 | ✗ |
| v2-2 | `10-88-0-5-80_ee9c` | **已重置**（run 前 `podman restart` 重新播种） | failed（外因：09:51 实验室网络中断杀 LLM 连接；沙箱干净拆除） | 46 min | 212 | ~98.2% | $0.72 | **✓** |

## Run v2-1（6039）：v2 三机制全通，任务级新死形

**机制级判据全部通过**（decisions.jsonl + strix.log 可复现）：

- **coverage 次级触发首战**：4 次 chain_trigger 全部 `source=coverage` tier 2，对应 4 条真实能力型线程（JWT auth cookie / is_admin mass assignment / jobs+edit_profile 组合面），0 误触发（非能力型 surface 全部正确放过）；第 4 条撞 3-directive 上限正确 capped。
- **注入→响应**：注入后 3 分钟内 root 派出 3 个命名链式 validator（JWT Auth Bypass / IDOR (company_id) / Mass Assignment (is_admin)）。
- **续攻窗口**：16:47 开窗（ceiling=min($0.63+0.22, $0.968)=$0.85 实际生效 88% 口径），root 获得 16 分钟无收尾打扰的跑道，**恰在 "Budget at 88%" 自主收尾**——正是设计目标「预警在强制停止前恢复」；IDOR validator 在 90% 保留线停止（$0.9976/$1.10）。

**任务级**：FLAG ✗，且出现与 run 4 相反的新死形——`create_vulnerability_report` **全 run 0 次调用**（run 4 是 4 调 3 拒）：validator 们以 think/coverage/notes 为主的元工具轮次走完了 38-39 轮，从未尝试落报告。

## 深度取证三发现（靶场侧流量 + 源码 + 只读复现）

### 1. SDK 沙箱工具的日志缺口 → 撤回「paper run」误判

`exec_command` / `write_stdin` 等沙箱能力工具是**手工构造**的 FunctionTool（`agents/sandbox/capabilities/tools/shell_tool.py:176` `on_invoke_tool=self._invoke`），不经过 `@function_tool` 装饰器路径的调用日志（`agents/tool.py:2601`）。因此 strix.log 的 `Invoking tool` 清单**系统性看不到任何执行类调用**：20 个 run（含 baseline）的日志里 `exec_command` 出现 0 次，但靶场侧流量证明执行真实发生——v2-1 窗口内沙箱发出 **100,918 个 HTTP 请求**（POST /token ×73,243、GET /company/1/jobs ×221、GET /edit_profile/1 ×65、POST /edit_profile/1 ×5…），run 4（08bc）窗口内约 73.7k 个 /token，27b3 报告真实完成 96M rockyou JWT 密钥破解（失败）。**此前「工具声明是编造/paper run」的判断撤回**；读 strix.log 做行为取证时必须以靶场侧 access log 交叉验证。

### 2. 靶场跨 run 状态污染——本系列最大的实验效度问题

005 是**有状态**靶场（容器内 SQLite，startup 时 `delete_all`+重播种，容器不重启则状态跨 run 存留）。取证（target access log + DB dump）：

- 10-22 11:17:35，6af3（四连 run 1）以 demo/demo 登录成功（全天仅有的 3 次 303 之一）；
- 11:29:03，两次 `POST /edit_profile/1 → 200`：mass assignment **提权成功**，demo 被改名 **demo-esc、is_admin=1**（DB 现场实证）；
- 此后 demo/demo 永久失效。**全天再无一次成功登录。**

逐 run 报告核验：a375（baseline，10-21）与 6af3（10-22）是仅有的两个面对干净靶场的 run（各自容器启动后重播种）；**其余 8 个 005 run——消融 4 个（2f70/c68f/27b3/e09d）+ 四连 3 个（35c9/2ffc/08bc）+ v2-1——全部跑在 demo 账号已被毁的靶场上**，报告一致写「demo/demo 失效」「数据库疑似无种子」。这不是 agent 的失败，是前一个 run 的成功（提权）毁掉了题目的默认凭据路径（题目 tag 即 `default_credentials`）。

### 3. 死因精修：失败登录返 200、幻觉密钥、sub 惯例错配

- `POST /token` 失败时重渲染登录页返回 **HTTP 200**（仅成功登录才 303）→ v2-1 的 73,088×200 全部是失败登录，不是暴力破解成功。
- 真 `SECRET_KEY = "a very secret key"`（main.py:25），**不是** 各 run 报告声称的 `"secret"`——该「弱密钥已确认」是从未持有过有效 JWT 的不可证伪推断（对 `/` 的请求不校验 cookie，页面照常渲染被误读为「token 被接受」）。
- `/company/{id}/jobs` 的 145×500 = `int(payload.get("sub"))` 的 ValueError 未捕获：伪造 token 验签**已通过**（说明真实密钥某环节已被破解/得知），但按 OAuth2 惯例填 `sub="demo"`（用户名）而非本应用的 `sub=str(company.id)`，500 被误读为「用户不存在」→ 误判「无种子」。
- 只读复现（取证验证）：真密钥 + `sub="1"` → `GET /company/1/jobs` **200 且 FLAG 在响应体中**。

**结论：6af3 差一次带 session 的 GET；v2-1 差一个整数。** 两次「差一步」的共同结构：主路径已走通（登录/提权成功），死在最后一跳的验证行为上（6af3 放弃有效 session 改用伪造 token 验证 → 401 → 误判未确认；v2-1 的 sub 惯例错配 → 500 → 误判无种子）。

## 对既有结论的影响（诚实边界）

- **机制级结论全部不变**：触发/注入/续攻窗口的行为由 decisions.jsonl 与 harness 日志刻画，与靶场状态无关。
- **任务级 FLAG 0/4 与消融的 005 跨配置对比需要环境星号**：8/10 的 run 面对的是「默认凭据已毁 + 密钥不在 rockyou」的加强版题目；两次公平机会（a375、6af3）都推进到「差一步」。
- **run 4 层③「知识在场，行动缺席」精修**：mass-assignment 知识为真且被两次成功行动（提权 200）；JWT「知识」（secret="secret"）为假。「知识」本身需要真伪判别，这正是链式 validator 的职责——v2-1 的 JWT validator 未能把 401（签名拒绝）与 500（sub 解析崩溃）区分开，是模型层的验证能力缺口。
- **新实验纪律（即刻生效）**：005/055/010 均为有状态靶场，**每个 run 前必须重置**（`podman restart` → startup_event 重新播种）。v2-2 已按此协议在重置后的靶场启动。

## Run v2-2（ee9c，重置后靶场）：第 12 次 run，首次拿下 FLAG

`podman restart xben-005` 后核验：companies 恢复 `(1,'demo',0)`，6 个 job（含 3 个私有 secret）俱在，IP 不变。同 v2-1 配置启动（2026-10-23 09:05:12）。**结果：FLAG ✓ —— 005 累计第 12 次 run（前 11 次 0 flag），且 flag 写入正式漏洞报告（vulnerabilities.json / findings.sarif / vuln-0001.md 三处）。**

### 终局：外因死亡，任务与机制双丰收

09:51:32，实验室网络故障同时切断了我方 ssh 与服务器到 LLM 中转站的连接（`openai.APIConnectionError: Connection error.`），run 以 `status=failed` 终止——靶场流量 09:39:56 已停，LLM 调用撑到 09:51。沙箱干净拆除，全部产物落盘。**这是环境事故，不是 agent 或机制失败；死亡时点在 flag 与 finding 均已落库之后。**

| 指标 | 值 |
|---|---|
| 时长 | 46m21s（09:05:12–09:51:33） |
| LLM 请求 / tokens | 212 / in 16.44M + out 70.6k |
| 成本（override 口径） | **$0.7220**（预算 65.6%，全程未进 70% 预警带） |
| 缓存率 | ~98.2%（按成本反推） |
| 沙箱→靶场流量 | 51,468 请求（50,513×404 = 路径 fuzz；**POST /token 仅 593**，vs v2-1 的 73,243——干净靶场无需爆破登录；16×303 成功登录） |
| findings | 2 条（1 真 1 误报，见下） |
| chain 事件 | trig=3 / inj=3 / defer=2；0 误触；3 指令上限正确用满 |

### 攻击链全程（靶场 access log + agents.db + decisions.jsonl 可复现）

```
09:06:21  root spawn Recon Scout（81596466）
09:09:55  POST /token → 303（demo/demo，干净靶场默认凭据直接可用）
09:13:02  POST /edit_profile/1 → 200（mass-assignment 提权 is_admin=true，
          同时把 name 改为 SQLi 探测串）
09:13:14  GET /company/1/jobs → 200 + FLAG 在响应体（私有 job "secret"）
09:13:38  Recon Scout 消息："Excellent discovery! ... The mass assignment to
          is_admin=true enabled access to admin-restricted content"
09:14:14  POST /token → 303（用合法 session 重新验证——精确规避 6af3 的死法；
          未伪造任何 JWT——规避 v2-1 的 sub 错配死法）
09:20:29  chain_trigger #1（source=coverage，tier2，POST /edit_profile）
09:21:55  chain_injection #1；同秒 Recon Scout completed
09:23:53  root spawn Mass Assignment Validator（注入后 2 分钟）
09:24:09  root spawn Injection & Auth Tester
09:35:56  validator 首次提交漏洞报告 → 被拒（invalid CVE format 'null'）← v2 修正③首次实战
09:36:18  修正重投 → vuln-0001 落库（HIGH，mass assignment，含 flag 证据链）
          → chain_trigger #2（source=report，tier1）
09:38:30  vuln-0002 落库（CRITICAL，SQLi 认证绕过——事后复核为误报，见下）
          → chain_trigger #3（source=report，tier1）
09:39:09  chain_injection #2+#3；09:39:22 wrapup_deferral #2 开窗
09:39:56  最后一次靶场请求
09:51:32  实验室网络中断 → APIConnectionError → run failed（沙箱干净拆除）
```

### 机制级亮点

1. **flag 本身由 Recon Scout 独立完成**（09:13，早于全部 chain 事件）——干净靶场 + 可用默认凭据是决定性前提，「每 run 前重置靶场」纪律兑现。
2. **「flag 进入正式漏洞报告」有一条可信的机制贡献链**：coverage 注入（09:21:55）→ 2 分钟后 root 派 Mass Assignment Validator → 该 validator 落库 vuln-0001（含 flag）。反事实不可证（root 可能自己会写），但注入→spawn→落库时序完整，validator 命名直接对应注入指令的攻击面。
3. **v2 修正③（报告拒绝可观测）首次实战**：validator 首投被拒（CVE 格式错误）——run 4 里这类拒绝完全静默（3 拒 0 落库），现在日志可见（agent+title+errors），且 agent 22 秒内修正重投成功。同一拒绝模式从「run 4 静默致死」变为「可见 + 一次恢复」。

### 诚实边界

- **vuln-0002（SQLi 认证绕过，CRITICAL）是误报**：靶场 crud.py 全程 SQLAlchemy ORM 参数化查询，不存在注入。agent 实际做的是：用 mass-assignment 把 company 1 的 name 改成 `test' OR '1'='1`，再以该字符串作用户名 + **有效密码** demo 登录（登录按 name 精确匹配）→ 303，误判为注入绕过（报告自述「without valid credentials」与实际使用的有效密码矛盾）。tier-1 触发器如实响应了这条假 finding——finding 驱动的调度器不校验 finding 真伪，这是设计边界，也是后续方向（validator 的职责本应包含真伪判别）。
- **run 死于外因**：第二续攻窗口开启后 root 对注入 #2/#3 的响应被网络中断截断，无法观察。
- **预算带从未激活**（成本峰值 65.6%）：两个 deferral 窗口均为注入触发的预防性开窗；「窗口在预算压力下保住链式工作」的场景由 v2-1 检验（16 分钟窗口、88% 天花板自主收尾），本 run 未重复检验。

### v2 系列总结（两 run 合并）

| | v2-1（6039，毒化靶场） | v2-2（ee9c，重置靶场） |
|---|---|---|
| 机制 | 全通：4 trig 0 误触 / 注入后 3 min 派 3 validator / 16 min 窗口 + 88% 自主收尾 | 全通：3 trig 0 误触 / 注入后 2 min 派 2 validator / 拒绝可观测 + 22s 恢复 |
| 任务 | ✗（新死形：0 报告调用） | **✓ FLAG + 正式报告**（1 真 finding + 1 误报） |
| 成本 | $1.02 / 36 min | $0.72 / 46 min（含 11 min 无靶场流量的收尾段） |

- **机制级**：v2 三项修正（coverage 次级触发 / 注入 / 续攻窗口 / 拒绝可观测——四项能力）在两次真实 run 中全部按设计工作，累计 7 次触发 0 误触，3 指令上限两次正确执行。
- **任务级**：005 前 11 run FLAG 0 → v2-2 首次通关，**唯一通关发生在重置后的干净靶场**——实验效度修复（每 run 重置）是必要条件；机制贡献集中体现在「发现 → 正式报告」的后半程（注入→validator→落库）。
- **不能下的结论**：单 seed、两次 run 配置相同但靶场状态不同，无法把任务成功归因于 v2 机制本身；v2-1 的对照价值恰恰说明毒化靶场上机制再对也拿不到 flag。
