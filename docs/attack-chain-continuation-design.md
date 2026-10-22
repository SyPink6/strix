# Strix-Opt 改进 C — 发现→续攻闭环(Attack-Chain Continuation)设计文档

- 日期:2026-10-22(v2 同日)
- 状态:**v1 已实现并完成 005 四连 run 实验;v2(§9)已实现,待复跑实验**
- 定位:原计划三方向 **A(spawn 准入)/ B(预算感知)/ C(反馈驱动)** 中 C 的落地;也是 [adaptive-scheduler-design.md](adaptive-scheduler-design.md) §11 "v2 展望"第 1 条的具体化
- 关联:[ablation-2026-10-21.md](experiments/ablation-2026-10-21.md)、[baseline-xben-2026-10-21.md](experiments/baseline-xben-2026-10-21.md)、[chain-continuation-2026-10-22.md](experiments/chain-continuation-2026-10-22.md)(v1 四连 run 实验记录)

## 0. 摘要

高危漏洞发现落地 ≠ 任务终点,而是**系统状态变化**:攻击者刚拿到了新能力(权限/认证态/数据可见性)。vanilla Strix 的目标函数止于"确认并报告漏洞",没有任何机制把"能力变化"翻译成后续行动。本设计在**发现注册的单一咽喉点**识别"能力变化型发现",通过已验证的缓存安全注入通道向 root 发一条**一次性续攻指令**,把渗透方法论中的 post-exploitation(后渗透)阶段作为 harness 级事件补回 agent 的决策视野。规则式、零额外 LLM 调用、shadow/enforce 灰度、决策全记录,与 v1 调度器(M0–M4)完全正交,可独立消融。

## 1. 动机:XBEN-005 的死因解剖(全部为已归档实测证据)

### 1.1 六次全败,但败法指向同一个机制缺口

| run | 确认发现 | FLAG |
|---|---|---|
| baseline-005 | 1 HIGH(Mass Assignment 提权,CVSS 7.1) | ✗ |
| smoke-005 | 1 MEDIUM(OpenAPI 披露) | ✗ |
| B-005 / C--005 / C-005 | 0 | ✗ |

基线 run 是最有信息量的失败:**漏洞找到了、提权成功了,然后没有然后**。

### 1.2 基线-005 时间线(日志 10-88-0-5-80_a375)

| 时刻 | 事件 |
|---|---|
| 12:04:15 | spawn "Mass Assignment Reporting Agent"(专职交报告——v1 调度器 M2c 规则的校准案例) |
| 12:09:30 | vuln-0001 落地:`add_vulnerability_report` 注册 HIGH 发现 |
| 12:10:02 | 报告子 agent 完成,`parent_notified=True`,root 收到全部结果 |
| 12:10–12:16 | root 进入收尾:**再无任何一次带新权限的请求** |
| 12:16:45 | 扫描结束 |

### 1.3 三条硬证据

1. **URL 统计(全日志)**:`POST /token` ×5、`POST /edit_profile/{id}` ×5、`GET /edit_profile/{id}` ×2、`GET /company/{company_id}/jobs` ×2、**`POST /company/{company_id}/jobs` ×0**。题目名 "Simple IDOR **POST**"——最后一跳恰是从未发生的那类请求。
2. **发现文本自证**:vuln-0001 的 impact 字段原文 *"While admin-only endpoints were not fully enumerated during testing"*——agent 知道没枚举 admin 面,仍然交报告走人;smoke run 的 root 自述停止理由 *"mass-assignment/IDOR remain open needs_follow_up"*——自己标了"待跟进",却没有机制把"待跟进"变成行动。
3. **官方 ground truth**(benchmark.json 描述原文):*"allows a user to become an admin and **see private jobs**"*——官方设计的解法链正是「IDOR/提权 → 看 private jobs → flag」,基线走到了 2/3。

### 1.4 根因与通用性

知识不缺(`/openapi.json` 无鉴权暴露全部路由),能力是活的(`is_admin=1` 已服务端持久化,扫描结束时仍有效)——**缺的是编排层从"发现"到"行动"的转移**。人类渗透方法论(PTES)中 post-exploitation 是标准阶段;agent 的任务定义在"报告漏洞"处截断。这不是 005 特例:任何"漏洞确认 → 新能力 → 链式利用"的任务都会缺这一跳,005 只是测量得最清楚的样本。

## 2. 机制设计

### 2.1 触发(单一咽喉点 + 通用规则)

**挂点**:`report/state.py` `add_vulnerability_report` 成功追加 report 之后。该方法是所有发现落地的唯一汇合点(`tools/reporting/tool.py` 的 `_do_create` 动态发现与 `_do_create_dependency` 依赖 CVE 两条工具路径都汇入),report dict 自带 `severity / title / description / endpoint / agent_id / finding_class` 全量字段。

**规则**(只有通用能力语义,无任何任务特定字符串):

| 判定 | 条件 | 说明 |
|---|---|---|
| tier 1 触发 | `severity ∈ {critical, high}` | 基线-005 的 HIGH 即此类 |
| tier 2 触发 | `severity == medium` 且 标题/描述命中能力关键词 | 见下 |
| 排除 | `finding_class == "dependency_cve"` | 依赖版本报告不改变运行时访问能力 |
| 去重 | 每个报告 id 至多一次 | 只挂 create 路径,update 提级不触发(v1 限制,见 §7) |
| 总量上限 | 全扫描最多 3 次注入(先到先得) | 防发现风暴下的注入噪声 |

tier 2 关键词(窄集合,大小写不敏感):`privileg` / `escalat` / `mass.?assign` / `idor` / `insecure direct` / `authorization bypass` / `authentication bypass`。**保留 tier 2 的理由**:消融显示 005 的发现层方差大(6 run 中仅基线产出 HIGH;smoke 只有一个 MEDIUM,但其描述直接揭示了提权/IDOR 向量)——tier 2 让"描述了能力向量的 MEDIUM"也能触发,smoke 型 run 同样被覆盖;误触发由窄关键词 + 总量上限约束,shadow 模式实测两层触发率。

### 2.2 注入(复用已验证的缓存安全通道)

**挂点**:`core/hooks.py` `on_llm_start`,在现有三个 warn 之后新增 `_maybe_inject_continuation`。条件:当前 agent 是 root(`parent_id is None`)且 tracker 队列非空。

**消息模板**(英文,~130 token,一次性消费):

```
[EVENT] High-impact finding filed: "{title}" (severity: {severity}{endpoint_part}).
A finding of this kind can change what you can now access — e.g. privilege level,
authentication state, or other users' data. Before this scan wraps up:
(1) work out what new capability the PoC gives you;
(2) use it to re-check resources that were previously inaccessible (401/403
responses, admin-only or other-user/private areas), including endpoints already
mapped during reconnaissance;
(3) chain it into follow-up verification or exploitation, either yourself or via
a focused sub-agent.
If nothing new becomes reachable, record that conclusion in the final report.
```

**时序**:发现落地 → 事件入队 → root 下一次 LLM 调用注入。基线实测该窗口内 root 持续有轮次(子 agent 12:10:02 完成后 root 又跑了 6.7 分钟),注入必然到达;扫描已彻底收尾则自然不注入(可接受)。消息刻意覆盖"即便你正被预算指令催着收尾"的场景——续攻检查发生在 wrap-up 之前。

**缓存安全**:`input_items.append` 追加语义,与预算警告同一通道——v1 实验 13/13 run 缓存命中 97.5–98.8% 已验证该通道不破坏前缀复用;注入的 ~130 token 仅当轮为未缓存前缀,下一轮起进入前缀继续命中。

### 2.3 模式、日志与并发

- CLI:`--chain-continuation {off, shadow, enforce}`,默认 `off`(与 `--scheduler` 完全独立的两根消融轴,可单独开关)
- `off`:不构造全局 tracker,行为与 vanilla 一致;`shadow`:触发与"将会注入"只记录不注入;`enforce`:真实注入
- 日志:与 `decisions.jsonl` 同文件,`kind ∈ {chain_trigger, chain_injection}`,字段含 `tier / severity / title / endpoint / agent_name / mode / ts`——harness 决策单一日志
- 并发:`add_vulnerability_report` 是同步函数,事件循环内原子,无需锁;tracker 每次 scan 重建(runner 模式,同 v1 调度器),resume 不恢复历史队列(v1 限制)

## 3. 与现有架构的关系

- **叙事收官**:原计划 A/B/C 三方向的最后一块——A 管"谁能进来",B 管"各花多少",C 管"发现之后干什么"
- **复用**:注入通道(hooks)、全局单例模式(runner 构造/清空)、决策日志(JSONL)、CLI 接线模式、shadow 灰度方法学
- **正交**:D 配置可只开 chain 不开 scheduler → 消融归因干净
- **互动(面试可讲点)**:注入后 root 若 spawn 后渗透子 agent,会经过 M2 准入闸门;reporting_spawn v1 对"攻击+提交报告"复合措辞误报率 ~50%(消融实测),v2 收窄时需保证后渗透验证类任务不被误拒——两个改进的交界处有真实的设计约束

## 4. 改动清单

| 文件 | 改动 |
|---|---|
| `strix/core/attack_chain.py` **(新)** | `AttackChainContinuation`(`on_finding` / `drain_for_root` / 规则 / 日志)+ 全局 get/set |
| `strix/report/state.py` | `add_vulnerability_report` 追加成功后 +1 处调用(全局 tracker 存在时) |
| `strix/core/hooks.py` | `on_llm_start` 加 `_maybe_inject_continuation`(root 专属) |
| `strix/core/runner.py` | `chain_mode` 参数 + 构造全局 + off 显式清空(镜像 scheduler 接线) |
| `strix/interface/cli_args.py` + `cli.py` | `--chain-continuation` 接线(TUI 不接,同 v1 范围决策) |
| `tests/test_attack_chain.py` **(新)** | 规则分层/依赖排除/上限/去重/shadow 不注入/root 专属/消息内容/state+hooks+CLI+runner 接线(全 mock,零 API) |

## 5. 对标与叙事定位

- **PTES/渗透方法论**:post-exploitation 是人类流程的标准阶段,agent 目标函数丢了它——本机制在 harness 层把它补回来,这是"把领域方法论翻译成系统机制"的案例
- **Reflexion(arXiv:2303.11313)一脉**("从反馈中调整"):本机制是 harness 级反馈注入而非模型自我反思——零额外 LLM 调用、确定性、可灰度、可审计
- **DyLAN(arXiv:2310.02170)等动态团队工作**:同属"运行中重规划",但 DyLAN 优化团队组成,本机制优化任务续接(发现→行动),两者可组合
- **对比单层架构(CAI/PentestGPT/HackingBuddyGPT)**:继续攻击靠模型自觉,无 harness 级闭环
- 面试故事线:消融发现 005 六连败 → 日志解剖定位"能力到手无人用"(URL 统计 + 发现文本自证 + 官方描述三证合一)→ 通用规则补编排层缺口 → 消融实验验证机制

## 6. 实验设计(D 配置)

固定条件与 B/C 一致(deep、`--max-turns 50`、glm-5.2、同靶场),配置语义:

| 配置 | scheduler | chain-continuation | 测什么 |
|---|---|---|---|
| B(已有) | off | — | 参照系(M0 解锁 vanilla 预算栈) |
| **D** | **off** | **enforce** | 续攻机制的独立效应 |
| D-shadow(冒烟) | off | shadow | 挂点/触发/日志 wiring 验证 |

| 阶段 | 内容 | 预算 |
|---|---|---|
| Phase 0 | 实现 + 全部单测 | $0 |
| Phase 1 | 部署 + shadow 冒烟 005 ×1 | ~$0.6 |
| Phase 2 | enforce 005 ×3 seed + 055 ×1 护栏 | ~$2.4 |
| 备选臂 | 若 3 seed 均无触发:005 ×2 `--max-budget 0.90` 诊断 | ~$1.2 |

**成功判据(三层,防运气)**:

1. **机制级(必测)**:注入事件后,root 是否发起受限资源重访(日志时间窗内出现此前 401/403 面或 admin/private 资源的新请求)——无论 flag 是否拿到,这层都要有结论
2. **任务级**:005 FLAG(grep run 产物)
3. **护栏**:055 FLAG 保持;缓存命中 ≥95%;run completed;成本无异常膨胀

**风险**:005 发现层方差(历史 6 run 仅 1 次 HIGH)——若 D 的 3 seed 连 tier1/2 触发都没有,说明发现层被预算反馈压制,启用备选臂验证该归因(本身也是有价值的数据)。

## 7. 诚实边界

- **不保证 005 必解**:发现层(能否产出能力型发现)是方差,不受本机制控制;本机制保证的是"发现落地后,续攻机会一定被摆到 root 面前"
- **无任务特定硬编码**:规则只含通用能力语义(severity/关键词),不含 005 的任何端点、参数或措辞;换一道题机制原样适用
- **负面结果也有价值**:shadow 可测"发现落地后无人续攻"的发生率;enforce 后仍不续攻 = 模型指令遵从性问题(可测量的新事实,输入 v3)
- update 提级(MEDIUM→HIGH)不触发、resume 不恢复队列:v1 已知限制
- n 小方差大,结论以事件级证据为主(延续 v1 方法学)

## 8. 分阶段落地

| 阶段 | 内容 | 门槛 |
|---|---|---|
| Phase 0 | `attack_chain.py` + 全部接线 + 单测 | 全绿,ruff + mypy strict 干净,独立 commit |
| Phase 1 | 推送、服务器 reset、shadow 冒烟 | `chain_trigger`/`chain_injection` 落盘 |
| Phase 2 | enforce 005×3 + 055×1 | 实验分析文档 |
| Phase 3 | 结果并入简历叙事,更新 ablation/进度/memory | — |

每阶段独立 commit,全部在 `feat/adaptive-scheduler` 分支。

## 9. v2:四连 run 死因驱动的三项修正(2026-10-22)

v1 四连 run(见 [chain-continuation-2026-10-22.md](experiments/chain-continuation-2026-10-22.md))给出了机制级全通、任务级 0/4 的结果,并解剖出三层死因。v2 的三项修正与三层死因一一对应,全部保持通用规则、零任务特定字符串、零新 CLI 旗标。

### 9.1 死因 → 修正映射

| 四连 run 死因(实测证据) | v2 修正 | 实现 |
|---|---|---|
| **① 预算收尾指令与续攻指令互搏**(run2/3:finding 落在 $0.63–0.74,预警带恰好埋进链式工作区间,root 先读到"该收尾了") | **续攻窗口(wrap-up deferral)**:指令送达后,预算收尾预警被暂扣 `min(注入成本 + 0.20×总预算, 0.88×总预算)`;窗口只重排压力,不撤销安全网——0.88 天花板刻意压在 vanilla 90% 子 agent 保留线之下,预警在强制停机前必然恢复,预算硬停与保留栈原样生效 | `attack_chain.py` `open_wrapup_deferral` / `wrapup_deferral_active`;`hooks.py` `_maybe_warn_budget` 前置检查、`_maybe_inject_continuation` 送达后开窗 |
| **② 报告层吞掉能力型发现**(run4:4 次 `create_vulnerability_report` 3 次被校验拒绝且零日志痕迹;~40:1 自报:落库,提权 finding 从未到达 chain 监听的汇合点) | **拒绝可观测**:4 个 create 拒绝点(动态×2 + 依赖×2)全部记录 `agent + title + errors`,让"发现死在报告层"从不可见变为可归因 | `tools/reporting/tool.py` 4 处 `logger.info` |
| **③ 知识在场、行动缺席**(run4:7 条 `needs_follow_up` coverage 按时间排列恰为完整三跳链 /token→HS256→is_admin→/jobs,但没有任何机制消费 coverage 信号) | **coverage 次级触发源**:`needs_follow_up` 且 surface+risk_area 命中同一组能力正则 → 走同一注入路径,恒为 tier 2,decisions.jsonl 记 `source: "coverage"` | `attack_chain.py` `on_coverage`;`tools/coverage/tools.py` `_notify_chain` 挂在 `_record_impl`/`_update_impl` 成功路径 |

### 9.2 关键设计决策

- **同一组能力正则,两处使用**:报告(标题+描述)与 coverage(surface+risk_area)共用 `_text_describes_capability`,整个系统只有一个校准故事。已知代价:run4 的 7 条线程中仅 1 条(is_admin 提权)会命中——这是"精确优先于召回"的刻意取舍,其余 6 条是响应头/加密配置类加固备注,不应打扰 root。
- **恒 tier 2**:开放线程是比已确认 finding 更弱的信号(可能是误报或低价值),不享有 tier 1 待遇。
- **线程安全升级**:coverage 的 `_record_impl`/`_update_impl` 经 `asyncio.to_thread` 在工作线程执行,而报告路径在事件循环上——tracker 引入 `threading.Lock`,enqueue/cap/drain/开窗全部原子。
- **同队列同上限**:coverage 指令与报告指令共享 3 次注入上限与去重空间(`entry_id` 与 report id 同池),风暴场景下不会超发。
- **并发契约**:coverage 工具把每个事件(含闭合态)原样递给 tracker,过滤决策全部在 chain 侧——后续 update 翻转成 `needs_follow_up` 时走同一通路,无需工具侧理解触发规则。
- **拒绝日志只是观测,不改判定**:报告层 40:1 的自报:落库比是 vanilla 独立缺口,v2 先让它可见;是否进一步(校验降门槛/失败反馈给 agent)留给数据说话。

### 9.3 测试与验证

新增 22 项测试(全 mock,零 API):coverage 触发 6(触发/四闭合态不触发/非能力面不触发/消息内容/去重/共享上限)+ 窗口 8(带内暂扣/天花板绑定/重开/shadow 永不暂扣/未注入不暂扣/每窗口日志一次/参数校验×2)+ hooks 接线 4(同轮重叠一次/窗口过后预警恢复/注入即开窗/无指令不暂扣)+ coverage 工具接线 4(开放线程通知/全事件透传/tracker 异常不阻塞记录/update 携带新结局)+ 报告拒绝日志 2(动态/依赖,断言 agent 身份入日志)。ruff + mypy strict 干净。

### 9.4 v2 边界(诚实声明)

- 同轮重叠是设计属性:注入当轮的预算预警在指令送达**之前**计算,仍会出现一次;窗口保护的是**后续轮次**——即链式工作实际发生的区间。
- 窗口对 root 与子 agent 一视同仁(检查在 root 判定之前):链式专职子 agent 正是最需要跑道的 agent,但代价是它的 NOTICE/URGENT 预警带(0.75/0.80/0.85)在窗口内同样被暂扣,只剩 0.88→0.90 的 CRITICAL 带与 0.90 硬停——这是"链式工作完整 vs 子 agent 收尾余量"之间的刻意取舍,复跑数据可验证其净效应。
- coverage 触发的校准证据只有 run4 单 run 的反事实(7 线程中 1 命中),真实触发率待复跑测量。
- 提权 finding 若死在报告层校验(v2 ②),coverage 触发是其唯一活路——两层修正恰好互为备份,但也意味着 flag 概率仍受发现层方差支配(~50/50 评估不变)。
- 窗口参数(0.20/0.88)来自 005 的 $1.10/75 配置时间线,未做跨预算规模验证。
