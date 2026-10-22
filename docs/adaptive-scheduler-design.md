# Strix-Opt 优化方案 v1 — 基于实测基线的预算感知调度

- 日期:2026-10-21
- 基线:[baseline-xben-2026-10-21.md](experiments/baseline-xben-2026-10-21.md)(3 题,$2.507 / 98.2 min / 584 请求 / FLAG 2/3)
- 状态:**Phase 0–3 全部完成**(2026-10-21):实现+单测 0 新增失败,smoke 与消融实验 B/C-/C 已跑完并产出 [experiments/ablation-2026-10-21.md](experiments/ablation-2026-10-21.md)

## 0. 摘要

基线测量暴露三类可优化的浪费:① 单 agent 无经济问责(010 的 Injection Validator 打满 50 轮,吃掉本题 29.5% 输入、53.7% 输出,仅产出 1 个 MEDIUM);② 无价值 spawn 无准入(005 为提交一次报告专门起了一个新 agent);③ 成本记账失效导致 vanilla 已有的全局预算控制整体哑火。本方案 = **M0 价格兜底(解锁 vanilla 存量预算栈)→ M1 per-agent 成本份额警告 → M2 spawn 准入控制 → M3 并发护栏 → M4 影子模式决策日志**,全部规则式、挂点式小改(2 个新文件 + 5 处小改),默认关闭、可回退。用消融实验 A(基线,已完成)/ B(仅 M0)/ C(全量)把"解锁存量机制"与"新增调度逻辑"的贡献分开测量。

## 1. 目标与成功标准

- **优化对象:成本与效率**。XBEN 官方 README 称题目已饱和(2026 业界≈100%),成功率无区分度。
- 主指标:离线成本/题、墙钟时间/题(离线口径与基线一致:未缓存输入 × $1.4e-6 + 输出 × $4.4e-6,与 run.json 对账)。
- **护栏指标(不达标即回退)**:FLAG 命中 ≥ 2/3;缓存命中率 ≥ 95%;报告发现数降幅 < 30%。
- 明确不做:成功率优化、重写 agent loop、模型式调度决策、修改 vanilla 默认行为(一切新增默认关闭)。

## 2. 基线证据 → 问题清单

| # | 问题 | 实测证据 |
|---|---|---|
| P0 | **成本记账失效,预算栈整体哑火** | litellm 价格目录 glm-5.2 有 9 个歧义条目 → `report/usage.py:277` 记账返回 None → `get_total_llm_cost()`≈0 → vanilla 的警告带、90% 预留停、`--max-budget` 全部永不触发;基线只能靠 `--max-turns 50` 兜底 |
| P1 | **单 agent 无经济问责** | 010 Injection Validator:恰好 50 请求(打满轮次上限被停),4.30M 输入(本题 29.5%)、64.2k 输出(本题 53.7%;输出单价是未缓存输入的 3.1 倍,成本占比更高),最终产出 1 个 MEDIUM |
| P2 | **无价值 spawn 无准入** | 005 "Mass Assignment Reporting":全新 agent context 只为调用一次报告工具;010 CVE Checker:产出全部为版本匹配型已知 CVE(MEDIUM/INFO),无利用链推进 |
| P3 | **spawn 零条件** | `core/execution.py:386` `spawn_child_agent` 收到即注册即跑,无预算/重复度/并发任何检查 |
| P4 | **缓存是成本生命线** | 44.0M 输入 token 中 98% 缓存命中,未缓存仅 ~0.86M。任何干预不得破坏 prompt 前缀复用 |

## 3. 原版能力盘点(复用,不重造)

通读 `core/hooks.py` 发现 vanilla 已内置完整的**全局**预算控制栈,设计质量不低:

| 已有能力 | 位置 | 说明 |
|---|---|---|
| per-request/per-agent token+cost 归因 | `report/usage.py` `LLMUsageLedger` | 基线的离线核算就建立在它之上 |
| 全局预算硬停 + pause 策略 | `core/hooks.py` `BudgetPausedError` | `--max-budget` + `budget_policy stop/pause` |
| 分级警告带 + 收尾指令 | `core/hooks.py:46-49` | root 0.70/0.85/0.95,子 agent 0.75/0.80/0.85,NOTICE/URGENT/CRITICAL 三级 wind-down 指令 |
| 子 agent 90% 预留停 | `core/hooks.py:50` `_SUBAGENT_BUDGET_RESERVE=0.90`,`SubagentBudgetReservedError` | 全局预算 90% 处单独停子 agent,为 root 最终报告留量 |
| 轮次警告 | `core/hooks.py:249` | `--max-turns` 的 0.70/0.85/0.95 带宽警告 |
| **缓存安全的注入模式** | `core/hooks.py:271,316` | `input_items.append({"role":"user",...})` —— 只追加不改写历史 |

**结论:v1 的本质是"解锁 + 补位",不是新建预算系统。** P0 修复后 vanilla 存量机制立即全部激活;我们真正新增的是"个体问责"(M1)、"入口准入"(M2/M3)和"决策可观测"(M4)三层 vanilla 完全没有的能力。

## 4. 设计原则

1. 复用现有引擎,挂点式小改,不重写 loop;
2. 规则先行,不上模型做调度决策;
3. 一切新增默认关闭(env/CLI 开关),保证 baseline 随时可复现;
4. 缓存安全一票否决:任何注入走 vanilla 的追加通道;
5. 贡献边界诚实(附录 B),提升幅度只报实测数字。

## 5. 架构与挂点

```
                     ┌────────────────────────────┐
  spawn_child_agent ─┤ M2/M3 decide_spawn()       ├─ 拒绝 → 结构化 JSON 给父 agent
  (execution.py:407后)│ M4  decision_log           │
                     └───────────┬────────────────┘
  on_llm_start ──────────────────┤ M1 check_agent_share()
  (hooks.py)                     ▼
                     ┌────────────────────────────┐
  usage.py / state.py┤ M0 价格兜底 → cost 变真     ├→ vanilla 全局预算栈自动激活
  (completion_cost处)└────────────────────────────┘
```

| 文件 | 改动 |
|---|---|
| `strix/core/adaptive_scheduler.py` **(新)** | `AdaptiveScheduler`(mode=off/shadow/enforce、task_budget、per_agent_share、max_children)+ `decide_spawn()` + `agent_share_status()` + 决策日志 |
| `tests/test_adaptive_scheduler.py` **(新)** | mock 单测,不烧 API |
| `strix/report/usage.py:257-277`(+ `report/state.py:1138-1170` 同步) | M0:`_fallback_cost()` 价格兜底 |
| `strix/core/execution.py:405` 之后 | M2/M3:spawn 前准入检查 |
| `strix/core/hooks.py` `on_llm_start` | M1:`_maybe_warn_agent_share()`,复用现有注入模式 |
| `strix/interface/cli_args.py` + `cli.py` + `core/runner.py` | `--scheduler {off,shadow,enforce}`(默认 off)与 `--per-agent-share`(默认 0.30)接线;runner 在 run_dir 就绪后构造全局调度器(decisions.jsonl 落在 run 目录),off 时显式清空全局——同进程多次扫描不串状态;TUI 路径本期不接(v1 范围外) |

## 6. 机制详述

### M0 价格兜底(解锁存量)——**已实现(Phase 0)**

- **语义**:`STRIX_PRICE_OVERRIDES` 配置的价格**优先于** litellm 目录(配置即生效,不依赖目录失败——避免目录解析到错误条目时静默错价)。未配置时行为与原版完全一致。
- **动作**:`cost = 未缓存输入 × p_in + 输出 × p_out + 缓存输入 × p_cached(默认 0)`;格式 `"模型=输入价,输出价[,缓存价]"`,多项用 `;` 分隔,坏条目告警跳过。缓存 token 从 `prompt_tokens_details.cached_tokens` / litellm 扁平键自适应读取。
- **落点**:两处 `completion_cost` 调用点共用 helper——`report/usage.py`(记账路径,喂 run.json 与预算钩子)与 `report/state.py`(实时回调路径);模型名做前缀剥离 + 裸名匹配。
- **效果链**:`get_total_llm_cost()` 变真 → vanilla 警告带 / 90% 预留停 / `--max-budget` 全部激活,**零新增执行逻辑**。
- **口径说明**:兜底价 = 内部控制信号,不等于中转站实际计费(缓存 token 计费策略未知,基线下界 $2.51 / 上界 $62.85);绝对值待中转站后台核对,但作为"何时该收尾"的相对信号完全够用。

### M1 per-agent 成本份额(个体问责)

- **触发**:某 agent 累计花费 ≥ `per_agent_share × task_budget`(默认 0.30)。
- **动作**:复用 vanilla 注入模式,向该 agent 追加**一次**英文收尾指令(与现有 wind-up directive 风格一致);shadow 模式只记日志不注入。
- **校准依据**:Injection Validator 实测占本题约三成消耗、打满轮次 → 0.30 份额会在其轨迹约 70-75% 处触发,恰好截断长尾。
- **与 vanilla 的关系**:vanilla 只有全局份额(所有 agent 共享一个总盘子),本机制补"个体"层。
- **只警告不硬停**:硬停由 vanilla 全局机制兜底,降低误伤概率;警告是否被 glm-5.2 遵从是实验 C 的直接测量项。

### M2 spawn 准入控制(入口把关)

三条规则,任一命中即拒绝,返回结构化 JSON(`{"success": false, "reason": ..., "suggestion": ...}`),模型可自行纠正:

| 规则 | 判定 | 校准依据 |
|---|---|---|
| (a) 预算地板 | 当前花费 ≥ `0.90 × task_budget` → 拒绝 | 单题基线 $0.64-0.97;地板语义复用 vanilla `_SUBAGENT_BUDGET_RESERVE`(子 agent 在 90% 处本就会被停,过了地板再 spawn 纯属浪费) |
| (b) 任务重复 | 与活跃 agent 任务 trigram Jaccard ≥ 0.80 → 拒绝 | 基线子任务文本区分度高,预期 0 触发——保留为廉价护栏 |
| (c) 报告型 spawn | 任务文本命中三条**窄模式**(见下)→ 拒绝并建议直接调报告工具 | 005 "Mass Assignment Reporting" 实证案例 |

M2(c) 的实现是三条开头句窄模式(大小写不敏感):`\byou are (a\|an\|the )?…reporting agent\b`、`\bfile (a\|the) …(vulnerability\|security\|finding) report\b`、`\breport (a\|the\|this) (confirmed\|documented\|above) finding\b`。对 13 条真实基线任务文本回归测试:恰好命中唯一的报告型任务,0 误报。**设计修正**:v1 方案的"报告关键词 + 已有发现才拒"被放弃——005 的报告 spawn 发生在**任何报告落地之前**(`vulnerability_reports` 为空),发现数门槛会让规则恰好漏掉它校准的那个案例;窄模式本身即信号(任务自述为 reporting agent),误报风险由 shadow 预跑兜底。

### M3 并发护栏(防御性)

- 活跃子 agent ≥ 4 时拒绝新 spawn(建议稍后再试)。
- 校准:055 实测峰值 root+4 且四个并行子 agent 全部有效 → cap=4 不改变基线行为。
- **诚实定位**:在这 3 题上预期不触发、不省钱,纯护栏;其价值在防更差 case,不计入优化收益。

### M4 影子模式 + 决策日志(可观测)

- `--scheduler shadow`:全部决策只记录不执行,输出 `decisions.jsonl`(时间戳 / 规则 / 当时额度 / 判定 / 相关上下文快照)。
- 用途:enforce 前验证信号质量(误报率统计);实验后做反事实分析("若启用会拒掉什么、省多少")。

## 7. 缓存安全分析(P4 一票否决项)

- vanilla 注入 = 轮开始时 `input_items.append`:历史前缀不动,新增 ~50 token;下一轮起该消息进入前缀继续命中 → **注入的缓存成本近似为零**。
- M1 警告、M2 拒绝 JSON 全部走追加语义通道,不改写任何历史消息、不碰 system prompt 拼接。
- 验收项:实验 C 结束后 run.json 缓存命中率应仍 ≈98%(< 95% 触发护栏回退)。

## 8. 实验设计(消融)

固定条件:同 3 题、同靶场(`start-targets.sh` 一键恢复)、deep 模式、`--max-turns 50`、glm-5.2、同一中转站。

| 配置 | 内容 | 测什么 | 预算 |
|---|---|---|---|
| A 基线 | vanilla,`--max-turns 50` | 参照系 | **已完成**($2.507) |
| B 仅 M0 | +价格兜底,`--max-budget 0.70` | "解锁存量"的独立价值:vanilla 全局栈激活后省多少、会不会杀 flag | ~$2.5 |
| C- 影子 | +M1-M4 shadow | 决策质量:会触发什么、误报率 | ~$2.5 |
| C 全量 | M0-M4 enforce,`--max-budget 0.70` | 新增调度的增量收益 | ≤$2.5 |

- `--max-budget 0.70` 校准:基线 005=$0.64(不绑定)、055=$0.90 / 010=$0.97(绑定)——恰好只压在有浪费观测的两题上。
- **假设(待实测,非承诺)**:B 把 055/010 压到 ≤$0.70 但有 flag 风险(这正是要测的);C 相对基线 055/010 成本 −15~25%、005 −5%(仅 M2c 生效)、墙钟持平或降、FLAG 保持 2/3。
- 方差诚实声明:每配置 n=1,LLM agent 高方差;<15% 的差异只作方向性参考;最终报告数字若需置信度再追加重复运行。
- 新增 API 花费合计 ≤$7.5(未缓存口径),**跑之前需你放行**。

## 9. 分阶段落地

| 阶段 | 内容 | 工作量 |
|---|---|---|
| Phase 0 | M0 + 单测(扩展 `test_pricing.py`) | **✅ 完成**(2026-10-21) |
| Phase 1 | scheduler core + M1-M4 + mock 单测 | **✅ 核心完成**(2026-10-21;`adaptive_scheduler.py` + ledger `agent_cost()` + hooks/execution 挂点,42+3 项新单测) |
| Phase 2 | CLI 接线(`--scheduler`/`--per-agent-share`/决策日志路径)+ 1 题 smoke 自测(~$0.3) | **✅ 完成**(2026-10-21;smoke 实测 $0.639,decisions.jsonl 落盘) |
| Phase 3 | B → C- → C 实验 + 分析文档 | **✅ 完成**(2026-10-21;10 run / $5.76 / 4h33m,见 ablation-2026-10-21.md;C vs C- 成本 -13%、请求 -21%,规则误报率 ~50% 是 v2 头号输入) |

每阶段独立 commit,全部在 `feat/adaptive-scheduler` 分支;baseline tag 永久保留作参照。

## 10. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 误拒/误警导致 flag 回退 | 默认关闭 + shadow 预跑统计误报 + B 先行单独测全局栈烈度 + 护栏指标强制回退 |
| 兜底价 ≠ 实际计费 | 控制信号与计费对账分离;中转站后台核对缓存 token 计费策略 |
| glm-5.2 不遵从收尾指令 | 实验 C 直接测量遵从率;不理想则 v1.1 升级 per-agent 硬停 |
| 单次运行噪声 | n=1 声明 + 方向性结论 + 可选重复运行 |
| 关键词规则误报 | shadow 日志先行统计,再决定 enforce |

## 11. v2 展望(本期不做)

- **发现驱动的预算再分配**:HIGH 发现落地时放宽后续相关 spawn 的准入——005 差一步的 flag(提权后未进 private jobs)或有解;
- per-agent 硬停、轮次-成本双维度止损;
- 按任务关键度的加权预算分配;
- 扩大评测题目数(n=3 → 更多,控方差)。

## 附录 A:阈值速查表

| 参数 | 值 | 来源 |
|---|---|---|
| glm-5.2 覆盖价 p_in / p_out | $1.4e-6 / $4.4e-6 per token | litellm 目录主流行情价(= 基线离线口径) |
| task_budget(`--max-budget`) | $0.70 | 基线三题成本的绑定面校准 |
| per_agent_share | 0.30 | Injection Validator 实测占比 |
| 报告型 spawn 模式 | 三条窄正则(开头句自述,见 §6 M2) | 13 条真实任务文本回归:1 命中 / 0 误报 |
| 任务重复阈值 | trigram Jaccard ≥ 0.80 | 设计假设(基线预期 0 触发) |
| max_children 并发 | 4 | 055 实测峰值 |
| vanilla 警告带(不动) | root 0.70/0.85/0.95,sub 0.75/0.80/0.85,reserve 0.90 | `core/hooks.py:46-50` 现值 |

## 附录 B:原版 vs 新增边界(诚实叙事)

| 原版已有(不贪功) | Strix-Opt 新增 |
|---|---|
| LLMUsageLedger per-request/per-agent token+cost 归因 | M0 价格兜底(配置化覆盖价,解锁歧义模型) |
| `--max-budget` 全局硬停 + stop/pause 策略 | M1 per-agent 成本份额警告(个体问责层) |
| 分级警告带 + wind-down 指令 + 90% 子 agent 预留停 | M2 spawn 准入(预算地板/任务去重/报告型 spawn 识别) |
| `--max-turns` 轮次上限 + 警告 | M3 并发护栏 |
| 追加式缓存安全注入模式 | M4 影子模式 + 决策日志(调度可观测) |
| dedupe 伪 agent(报告 LLM 去重) | 消融实验方法学(A/B/C 分离存量解锁与新增调度) |
| 基线测量与阈值校准方法 | |
