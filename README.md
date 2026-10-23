<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### The open-source AI pentesting tool. Autonomous AI hackers that find and fix your app’s vulnerabilities.

<br/>


<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://app.strix.ai?utm_source=github&utm_medium=readme&utm_content=badge_cloud"><img src="https://img.shields.io/badge/Strix%20Cloud-app.strix.ai-2b9246?style=for-the-badge&logoColor=white" alt="Strix Cloud"></a>
<a href="https://strix.ai/demo?utm_source=github&utm_medium=readme&utm_content=badge_demo"><img src="https://img.shields.io/badge/Try%20Strix%20Enterprise-555555?style=for-the-badge&logoColor=white" alt="Try Strix Enterprise"></a>

<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI Version"></a>


<a href="https://discord.gg/strix-ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/Discord.png" height="40" alt="Join Discord"></a>
<a href="https://x.com/strix_ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/X.png" height="40" alt="Follow on X"></a>


<a href="https://trendshift.io/repositories/15362?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-15362" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/15362/weekly" alt="usestrix%2Fstrix | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>

---

<div align="center">

## 🧪 Strix-Opt — This Fork's Additions

**Budget-aware adaptive scheduling & finding-driven attack-chain continuation for the multi-agent pentesting harness**

Research fork of [usestrix/strix](https://github.com/usestrix/strix) ·
baseline: tag [`baseline-1.7.0`](https://github.com/SyPink6/strix/tree/baseline-1.7.0) (upstream Strix 1.7.0) ·
dev branch: [`feat/adaptive-scheduler`](https://github.com/SyPink6/strix/tree/feat/adaptive-scheduler)

Everything after this section is upstream Strix documentation, kept as-is.（本节以下为上游原文档，原样保留。）

</div>

**Goal:** keep task-completion quality while cutting token/API cost, and turn "knowledge in the transcript" into "action on the target" — optimizing the *multi-agent harness*, not the model. No model training, no agent-loop rewrite: every change hooks into an existing convergence point (`spawn_child_agent`, `add_vulnerability_report`, `on_llm_start`). Evaluated on XBOW Validation Benchmarks (XBEN) web-security tasks, driven by glm-5.2.

| Addition | Mechanism | Measured evidence (XBEN) |
|---|---|---|
| **M0 — pricing override**<br>`STRIX_PRICE_OVERRIDES` | Fixes ambiguous LiteLLM price-catalog entries that resolved to `cost = 0` and silently disabled upstream's *entire* budget stack; overrides take priority over the catalog | Budget stack unlocked: agents self-wrapped-up at 87% budget; 4 child agents across 2 runs correctly stopped by the 90% reserve line (never fired before the fix) |
| **Adaptive scheduler**<br>`--scheduler {off,shadow,enforce}` | Spawn admission (budget floor → reporting-spawn detection → trigram-Jaccard task dedup → concurrency cap) + per-agent cost ceiling + structured denials with suggestions + JSONL decision log | Ablation (enforce vs shadow): **−13% cost, −21% requests**; all 3 denials self-corrected by the root agent within 35 s; prompt-cache hit 97.5–98.8% preserved |
| **Attack-chain continuation**<br>`--chain-continuation {off,shadow,enforce}` | Finding-driven continuation directives injected to the root agent: tiered trigger rules (critical/high; medium + capability keywords), coverage `needs_follow_up` secondary trigger, cache-safe root-only injection channel, wrap-up deferral window, report-rejection observability | **Zero rule-level false triggers** across all chain-enabled runs (9 fires in 6 runs; DoS / header / version-disclosure findings correctly passed). On stateful target XBEN-005-24: first flag in 12 runs, captured on the first run after the per-run target-reset protocol ($0.72 = 65.6% of a $1.10 budget, ~98% cache), with the flag reaching a formal vulnerability report via the injection → validator → filing chain |

```bash
# All additions are opt-in; defaults reproduce upstream behavior exactly
strix --target http://your-app \
  --scheduler enforce \
  --per-agent-share 0.30 \
  --chain-continuation enforce

# Pricing fallback for models missing from (or ambiguous in) the LiteLLM catalog
export STRIX_PRICE_OVERRIDES="model-name=input_price,output_price[,cached_input_price]"
```

New modules: [`strix/core/adaptive_scheduler.py`](strix/core/adaptive_scheduler.py) (spawn admission, per-agent share, decision log) ·
[`strix/core/attack_chain.py`](strix/core/attack_chain.py) (trigger rules, directive queue, deferral window) ·
[`strix/report/pricing.py`](strix/report/pricing.py) (price overrides), plus small hooks in `hooks.py` / `execution.py` / `runner.py` / coverage / reporting —
**13 files changed, +1176/−6 lines, 77 new tests**; ruff + mypy `--strict` clean; zero new test failures vs the baseline tag.
All numbers above are single-seed (n = 1 per config) real measurements, and task-level success is *not* causally attributed to the mechanisms — the explicit boundaries are in [诚实边界](#诚实边界) below.

## 🧪 Strix-Opt 新增内容详解

### 定位与边界

不重写 Agent Loop、不训练模型，只做多 Agent harness 层的调度与成本优化。
**上游 Strix 已有**（非本 fork 贡献）：全局预算与 70%/90% 预警/保留带、per-agent token/cost 归因（LLMUsageLedger）、多 Agent 协作与沙箱、`finish_scan` 中的静态 attack-chaining gate（仅收尾时检查）。
**本 fork 新增**：定价兜底、spawn 准入与个体配额决策、finding 驱动的动态续攻、续攻窗口、报告拒绝可观测、`decisions.jsonl` 决策审计、shadow/enforce 灰度模式。

选型依据（为什么是 Strix、与 XBOW / CAI / HackingBuddyGPT 的横向对比）见 [`docs/agent-landscape-2026-10.md`](docs/agent-landscape-2026-10.md)。

### 创新点 1：M0 定价兜底——先救活上游"死掉"的预算栈

LiteLLM 价格目录对部分模型（如 glm-5.2）存在歧义条目 → 成本解析返回 `None` → cost 恒为 0 → 上游的预算预警带/保留线/自主收尾**从未生效过**。`STRIX_PRICE_OVERRIDES` 以"override 优先于目录"的设计兜底（避免歧义目录静默解析到错价），在两处计费调用点前置生效。消融实验给出因果证据：修复后 87% 预算处 agent 自主收尾、2 个 run 共 4 个子 agent 被 90% 保留线正确停止让位 root——这些是上游代码里就有、但从未触发过的能力。

### 创新点 2：自适应调度器——spawn 准入 + 个体问责

上游 spawn 子 agent 零准入；per-agent 成本归因虽有数据、但无人消费。调度器在 `spawn_child_agent` 执行入口做四级准入（预算地板 → 报告型 spawn 识别，窄正则在 13 条真实基线任务上回归校准 → trigram-Jaccard 任务去重，阈值 0.80 → 并发 cap），每个 agent 另有成本天花板（默认 30% 预算，warn-once）。**拒绝时返回带建议的结构化 JSON**，root 可自我修正——实验中 3 次拒绝全部在 35 秒内按建议重 spawn，零中断。shadow 模式零行为变化可安全灰度；每条决策落 `decisions.jsonl` 可审计。

### 创新点 3：攻击链续攻——「静态门 → 动态事件」

取证显示：agent 把整条三跳攻击链的知识写进了 coverage/notes，却从未行动——上游唯一的 attack-chaining 检查是 `finish_scan` 里的静态 gate（收尾时才问一句）。本机制把它变成 **finding 驱动的动态事件**：`add_vulnerability_report` 这个唯一汇合点落库能力变化型 finding 时（tier1 = critical/high；tier2 = medium + 能力关键词，规则全通用、零题目特异串），经 cache-safe 通道向 root 注入一次性续攻指令；同 report 去重、每 run 3 条上限。四连 run 实验：机制五步全通（触发→注入→root 10-11 分钟内派出链式专职 agent），低危/DoS/响应头类 finding 全部正确不触发，**规则层误触发 0 次**。

### 创新点 4：v2 三修正——每条对应一个取证出的死因

| 修正 | 对应死因（取证） | 实测证据 |
|---|---|---|
| **续攻窗口**：指令送达后预算收尾预警暂扣至 min(注入成本 + 20% 预算, 88% 预算)，只重排不撤安全网 | 收尾指令与续攻指令互搏（四连 run2/3，链式 agent 被预警带 4-7 分钟晾死） | v2-1：16 分钟无打扰窗口，root 恰在 88% 天花板**自主**收尾 |
| **coverage 次级触发**：`needs_follow_up` 能力型 surface 作为第二触发源 | 能力信号死在报告层（run4：自报 ~40 findings 仅 1 条落库） | v2-1 的 4 次触发全部对应真实能力线程；v2-2 正是 coverage→注入→validator 链路把 flag 送进正式报告 |
| **报告拒绝可观测**：4 个拒绝点记录 agent + title + errors | 拒绝静默（run4：3 次拒绝 0 落库） | v2-2 首战：首投被拒（CVE 格式错误）日志可见，22 秒修正重投成功 |

### 工程特质

- **缓存前缀安全是设计约束**：所有注入走与预算警告相同的 cache-safe append 通道，全系列 run prompt-cache 命中 97-98%——成本优化不破坏缓存。
- **可审计 + 可灰度**：每条调度/续攻决策落 `decisions.jsonl`；shadow 模式零行为变化。
- **最小侵入**：挂点全在现有汇合点，13 个文件 +1176/−6 行，77 个新测试，ruff + mypy strict 干净，对照 baseline tag 零新增失败。

### 方法论：实验效度治理

靶场侧流量取证发现两个系统性问题并建立对应纪律：①**有状态靶场跨 run 污染**——10 个 005 run 里 8 个跑在被前 run 提权毁掉默认凭据的靶场上（报告一致误判"默认凭据失效"），由此建立**每 run 前重置靶场**协议；②**SDK 沙箱工具日志缺口**——harness 日志系统性看不到执行类工具调用，行为取证必须与靶场 access log 交叉验证。修复实验效度后，005 在第 12 次 run（首个干净靶场 + 完整机制）8 分钟内首夺 flag。

### 实验总览（全部真实测量；模型 glm-5.2，离线成本口径 = 未缓存输入×价 + 输出×价）

| 系列 | Run 数 | 花费 | 关键结果 |
|---|---|---|---|
| 基线（上游原版，3 题 L1/L2/L3） | 3 | $2.51 | FLAG 2/3；98.2 min；005 差最后一跳 |
| 消融 B / C- / C | 10 | $5.76 | M0 解锁预算栈（87% 自主收尾、4 子 agent 被 90% 保留线停止）；C vs C- 成本 **-13%**、请求 **-21%**；缓存 97.5-98.8% |
| 攻击链四连 run（005） | 4 | $4.29 | 机制五步全通、规则层误触 0；无预算对照 $2.00/1 finding vs $0.89/4 findings（预算感知的正面证据） |
| v2 复跑（005，重置纪律） | 2 | $1.74 | 7 次触发 0 误触；**v2-2 首夺 FLAG**（$0.72 / 65.6% 预算 / 212 请求 / ~98.2% 缓存），flag 经注入→validator→落库进入正式漏洞报告 |
| **合计** | ~20 | **≈$14.4** | |

### 诚实边界

- **单 seed**（n=1/配置）：不能把任务级成功（FLAG）归因于机制；干净靶场（重置协议）是必要条件，机制贡献集中在「发现 → 正式报告」的后半程。
- v2-2 的 1 条 SQLi CRITICAL finding 经代码复核为**误报**（靶场全程 ORM 参数化）——finding 驱动的调度不校验 finding 真伪，这是设计边界，也是后续方向。
- 其中 1 个 run 死于实验室网络中断（外因，且死亡发生在 flag 与 finding 落库之后）。

### 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/adaptive-scheduler-design.md`](docs/adaptive-scheduler-design.md) | M0 + 调度器设计（vanilla vs 新增边界、规则校准） |
| [`docs/attack-chain-continuation-design.md`](docs/attack-chain-continuation-design.md) | 攻击链设计（§9：v2 三修正与死因映射） |
| [`docs/experiments/baseline-xben-2026-10-21.md`](docs/experiments/baseline-xben-2026-10-21.md) | 上游基线测量（3 题） |
| [`docs/experiments/ablation-2026-10-21.md`](docs/experiments/ablation-2026-10-21.md) | 消融实验 B/C-/C（10 run） |
| [`docs/experiments/chain-continuation-2026-10-22.md`](docs/experiments/chain-continuation-2026-10-22.md) | 攻击链四连 run + v2 复跑 + 深度取证 |
| [`docs/agent-landscape-2026-10.md`](docs/agent-landscape-2026-10.md) | AI 渗透测试 agent 竞品格局与 Strix 架构亮点（选型依据） |

---

> [!TIP]
> **New!** Strix integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production - [Get started with no setup required](https://app.strix.ai?utm_source=github&utm_medium=readme&utm_content=tip_ci).

---


## Strix Overview

Strix are autonomous AI penetration testing agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual proofs-of-concept. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

**Key Capabilities:**

- **Full pentesting toolkit** - reconnaissance, exploitation, and validation out of the box
- **Multi-agent orchestration** - teams of AI pentesters that collaborate and scale
- **Real exploit validation** - working PoCs, not false positives like legacy vulnerability scanners
- **Developer‑first CLI** - actionable findings with remediation guidance
- **Auto‑fix & reporting** - generate patches and compliance-ready pentest reports


<br>


<div align="center">
  <a href="https://strix.ai">
    <img src=".github/screenshot.png" alt="Strix Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>


## Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities in your applications
- **Rapid Penetration Testing** - Get penetration tests done in hours, not weeks, with compliance reports
- **Bug Bounty Automation** - Automate bug bounty research and generate PoCs for faster reporting
- **CI/CD Integration** - Run tests in CI/CD to block vulnerabilities before reaching production

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key from any [supported provider](https://docs.strix.ai/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)

### Installation & First Scan

```bash
# Install Strix
curl -sSL https://strix.ai/install | bash

# Configure your AI provider
export STRIX_LLM="openrouter/z-ai/glm-5.3"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
strix --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `strix_runs/<run-name>`

### Updating

```bash
# Self-update the standalone binary to the latest release
strix --update

# ...or re-run the installer
curl -sSL https://strix.ai/install | bash
```

Installed with pipx, uv, or pip? `strix --update` prints the matching upgrade command instead (`pipx upgrade strix-agent`, `uv tool upgrade strix-agent`, `pip install --upgrade strix-agent`). Strix also shows a notice with the right command when a new version is available.

---

## Ways to Run Strix

- **Open Source** - free, runs locally with Docker and your own LLM key. [Quick Start](https://docs.strix.ai/quickstart)
- **Strix Cloud** - no setup, validated findings, one-click autofix, and PR reviews. [Run a pentest →](https://app.strix.ai?intent=pentest&utm_source=github&utm_medium=readme&utm_content=table_cloud)
- **Enterprise** - SSO, compliance-ready reports, VPC or self-hosted deployment. [Try Strix Enterprise →](https://strix.ai/demo?utm_source=github&utm_medium=readme&utm_content=table_demo)

---

## ☁️ Strix Cloud

Try the Strix full-stack penetration testing platform at **[app.strix.ai](https://app.strix.ai?utm_source=github&utm_medium=readme&utm_content=cloud_heading)** - sign up for free, connect your repos and domains, and launch a pentest in minutes.

- **Validated findings with PoCs** - every vulnerability includes a working proof-of-concept exploit and reproduction steps
- **One-click autofix** - AI-generated security patches as ready-to-merge pull requests
- **Continuous pentesting** - always-on vulnerability scanning that keeps pace with your deployments
- **DevSecOps integrations** - GitHub, GitLab, Bitbucket, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** - AI that builds on past findings, adapts to your codebase, and reduces false positives over time

[**Run a pentest →**](https://app.strix.ai?intent=pentest&utm_source=github&utm_medium=readme&utm_content=cloud_cta)

## 🏢 Enterprise

Get the same Strix experience with enterprise-grade controls: SSO (SAML/OIDC), custom compliance-ready penetration testing reports (SOC 2, ISO 27001, PCI DSS), dedicated support and SLA, custom deployment options (VPC or self-hosted), BYOK model support, and tailored AI pentesting agents optimized for your environment.

[**Try Strix Enterprise →**](https://strix.ai/demo?utm_source=github&utm_medium=readme&utm_content=enterprise_cta)

---

## 🤖 Use Strix from Your Coding Agent

Strix is agent-ready. Give Claude Code, Cursor, Codex, or any [SKILL.md-compatible](https://agentskills.io) agent the ability to run pentests, fix findings, and set up CI scanning:

```bash
npx skills add usestrix/strix
```

This installs nine skills for running pentests, fixing findings, and CI scanning, against code, web apps, APIs, and the OWASP Top 10. Agents can use the local CLI or the managed cloud with the same engine.

See [`AGENTS.md`](AGENTS.md) for the quick reference, [docs.strix.ai/llms.txt](https://docs.strix.ai/llms.txt) for the CLI, and [docs.app.strix.ai](https://docs.app.strix.ai) for the API.

---

## ✨ Features

### Agentic Pentesting Tools

Strix agents come equipped with a comprehensive offensive security toolkit - the same tools used by professional penetration testers and ethical hackers:

- **HTTP Interception Proxy** - Full request/response manipulation and analysis with Caido
- **Browser Exploitation** - Automated browser for testing XSS, CSRF, clickjacking, and auth bypass flows
- **Shell & Command Execution** - Interactive terminal for exploit development and post-exploitation
- **Custom Exploit Runtime** - Python sandbox for writing and validating proof-of-concept exploits
- **Reconnaissance & OSINT** - Automated attack surface mapping, subdomain enumeration, and fingerprinting
- **Static & Dynamic Code Analysis** - SAST + DAST capabilities for comprehensive application security testing
- **Vulnerability Knowledge Base** - Structured findings with CVSS scoring and OWASP classification

### Comprehensive Vulnerability Scanner

Strix identifies, validates, and exploits a wide range of security vulnerabilities across the OWASP Top 10 and beyond:

- **Broken Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL injection, NoSQL injection, OS command injection, SSTI
- **Server-Side Vulnerabilities** - SSRF, XXE, insecure deserialization, RCE
- **Client-Side Attacks** - XSS (stored/reflected/DOM), prototype pollution, CSRF
- **Business Logic Flaws** - Race conditions, payment manipulation, workflow bypass
- **Authentication & Session** - JWT attacks, session fixation, credential stuffing vectors
- **Infrastructure & Cloud** - Misconfigurations, exposed services, cloud security issues
- **API Security** - Broken authentication, mass assignment, rate limiting bypass

### Graph of Agents (Multi-Agent Pentesting)

Advanced multi-agent orchestration for comprehensive automated penetration testing:

- **Distributed Pentesting** - Specialized AI agents for recon, exploitation, and post-exploitation
- **Scalable Security Testing** - Parallel execution across multiple targets for fast, comprehensive coverage
- **Dynamic Coordination** - Agents share discoveries, chain vulnerabilities, and collaborate like a red team

---

## 🖥️ Local Web Viewer

Every scan writes its results to disk as it runs. Bring them up in a local dashboard with a single command:

```bash
# Open the most recent run
strix view

# ...or open a specific run by name
strix view my-run-name

# Expose the viewer on all IPv4 interfaces at a fixed port
strix view --host 0.0.0.0 --port 8080 --no-open
```

The dashboard shows the findings, a live map of the agent team, and past runs. Nothing leaves your machine, and the UI ships prebuilt. `strix view` binds to `127.0.0.1` and prints a tokened link that grants access to the run, so share it carefully.

See the [viewer documentation](https://docs.strix.ai/usage/viewer) for the options and for reaching the viewer from another machine.

---

## Usage Examples

### Basic Usage

```bash
# Scan a local codebase
strix --target ./app-directory

# Security review of a GitHub repository
strix --target https://github.com/org/repo

# Black-box web application assessment
strix --target https://your-app.com
```

### API Testing (OpenAPI / Swagger / Postman)

Point Strix at an API contract and it tests every declared endpoint instead of
having to discover them by crawling. Pair the spec with the live base URL so the
agent knows where to send traffic:

```bash
# OpenAPI / Swagger file, Postman export, or a live collection by id
strix --target ./openapi.yaml --target https://api.your-app.com
strix --target postman://<collection-uuid> --target https://api.your-app.com
```


### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# Targets from a file, one target per non-empty, non-comment line
strix --target-list ./targets.txt
```

See the [CLI reference](https://docs.strix.ai/usage/cli) for every option, including scan modes, diff scope, instruction files, and budgets.

### Headless Mode

Run Strix programmatically without interactive UI using the `-n/--non-interactive` flag - perfect for servers and automated jobs. The CLI prints real-time vulnerability findings and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

```bash
strix -n --target https://your-app.com
```

### CI/CD (GitHub Actions)

Strix can be added to your pipeline to run a security test on pull requests with a lightweight GitHub Actions workflow:

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./ --scan-mode quick
```

> [!TIP]
> In CI pull request runs, Strix automatically scopes quick reviews to changed files, which is why the
> checkout above fetches full history. See the
> [CI/CD documentation](https://docs.strix.ai/integrations/github-actions) for the details.

### Configuration

```bash
export STRIX_LLM="openrouter/z-ai/glm-5.3"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.
> See the [configuration reference](https://docs.strix.ai/advanced/configuration) for every environment variable.

#### Sign in with a ChatGPT subscription

Instead of a metered API key, you can run Strix on your ChatGPT Plus/Pro subscription:

```bash
strix auth login chatgpt             # sign in with your ChatGPT account
export STRIX_LLM="chatgpt/gpt-5.4"   # chatgpt/<model> runs on the subscription
strix auth status                    # show the active sign-in, or logout to forget it
```

#### Use the managed platform: `strix cloud`

Run scans on [app.strix.ai](https://app.strix.ai) from the terminal, without Docker or an LLM key:

```bash
strix cloud login                                  # browser sign-in, one credential per install
strix cloud scans start --source . --yes --wait    # scan local code, approving the upload
strix cloud scans start --engagement-type live_test --domain-ids <uuid> --wait
strix cloud vulns list --severity critical
```

Every [REST API](https://docs.app.strix.ai) operation has a matching `strix cloud <resource> <verb>` command. Run `strix cloud` to list the resources, and add `help` to a resource to list its verbs. Output is JSON when stdout is not a terminal or when you pass `--json`. Binary downloads are the exception: redirect the raw bytes, or combine `--output FILE --json` for download metadata.

See the [cloud CLI documentation](https://docs.strix.ai/cloud/cli) for scopes, workspaces, billing, and source-upload options.

#### Connect your own MCP servers

Strix can connect to Model Context Protocol (MCP) servers you list and expose their tools to the agent during a run. Create `~/.strix/mcp-servers.json` with a JSON list of local `stdio` servers or remote `http` servers:

```json
[
  {
    "name": "github",
    "transport": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "auth": { "kind": "bearer", "token": "your-token" },
    "allowed_tools": ["list_issues"]
  }
]
```

Each server's tools are namespaced by `name`, for example `github_list_issues`. See the [MCP documentation](https://docs.strix.ai/integrations/mcp) for the full schema, tool filtering, and `stdio` servers.

**Recommended models for best results:**

- [Z.ai GLM-5.3 on OpenRouter](https://openrouter.ai/z-ai/glm-5.3) - `openrouter/z-ai/glm-5.3` (the default pick)
- [OpenAI GPT-5.4](https://openai.com/api/) - `openai/gpt-5.4`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) - `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-3-pro-preview`
- [DeepSeek V4 Pro](https://platform.deepseek.com) - `deepseek/deepseek-v4-pro`
- [Moonshot Kimi K3](https://platform.kimi.ai) - `moonshot/kimi-k3`

See the [LLM Providers documentation](https://docs.strix.ai/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

## Documentation

Full documentation is available at **[docs.strix.ai](https://docs.strix.ai)** - including detailed guides for usage, CI/CD integrations, skills, and advanced configuration.

## Contributing

We welcome contributions of code, docs, and new skills - check out our [Contributing Guide](https://docs.strix.ai/contributing) to get started or open a [pull request](https://github.com/usestrix/strix/pulls)/[issue](https://github.com/usestrix/strix/issues).

## Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/strix-ai)**

## Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## Acknowledgements

Strix builds on the incredible work of open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Bubble Tea](https://github.com/charmbracelet/bubbletea). Huge thanks to their maintainers!


> [!WARNING]
> **Authorized use only.** Strix actively tests the targets you point it at, so only run it against systems you own or have **explicit, written permission** to test, and stay within the agreed scope. Unauthorized testing is illegal in most jurisdictions.
> You alone are responsible for obtaining authorization and complying with the law. Strix is provided "as is" with no warranty or liability for misuse.

</div>
