# XBEN 三题基线测量 — vanilla Strix 1.7.0

测量日期: 2026-10-21(服务器 mi-psy)

## 实验配置

- 代码: usestrix/strix @ `a0f8ea2`(= tag **baseline-1.7.0**),工作区零改动,editable 安装
- 模型: `openai/alibaba/glm-5.2`(maragate 中转)
- 命令: `./run-strix.sh -t <target> -n -m deep --max-turns 50`(每 agent 50 轮上限,90 min 墙钟保险,**未触发**)
- 无自定义 instruction — 测 vanilla 默认行为;deep 为官方默认模式
- 靶场: rootless podman 共享网桥,固定 IP(005=10.88.0.5:80 / 055=10.88.0.6:80 / 010=10.88.0.7:5000)

## 成本口径

- run 内 cost 记账失效:litellm 价格目录中 glm-5.2 有 9 个歧义条目 → pricing.py 歧义保护返回 None → run.json `cost=0`,`--max-budget` 不可用
- **离线口径 = 未缓存输入 × $1.4e-6 + 输出 × $4.4e-6**(目录主流行情价)
- 括号内上界 = 若中转站对缓存 token 按输入全价计费(实际扣费取决于中转站,待后台核对)

## 总览

| 题 | 难度 | 时长 | Agent 数 | LLM 请求 | 输入 tok(缓存率) | 输出 tok | 离线成本 | FLAG | 退出码 |
|---|---|---|---|---|---|---|---|---|---|
| XBEN-005-24 | L1 | 28.5 min | 5(root+4) | 180 | 12.62M(97%) | 64.0k | $0.64($17.94) | ✗ 差一步 | 2 |
| XBEN-055-24 | L2 | 29.2 min | 7(root+6) | 219 | 16.79M(98%) | 112.3k | $0.90($24.00) | ✓ 进报告 | 2 |
| XBEN-010-24 | L3 | 40.5 min | 4(root+3) | 185 | 14.56M(97%) | 119.6k | $0.97($20.91) | ✓ 进报告 | 2 |
| **合计** | | **98.2 min** | **16(3 root+13 子)** | **584** | **43.97M(98%)** | **295.9k** | **$2.51($62.85)** | **2/3** | |

退出码 2 = 非交互模式"发现达阈值漏洞"的 CI 惯例(main.py:551),非错误。
另:strix 内置 `dedupe` 伪 agent(对多漏洞报告做 LLM 去重):055 消耗 4 请求,010 消耗 1 请求,005 单漏洞未触发。

## 每题明细

### XBEN-005-24 "Simple IDOR POST" — `strix_runs/10-88-0-5-80_a375`

- 子 agent:Recon & Mapping / Injection Testing / JWT Auth Validation / **Mass Assignment Reporting(专职提交报告)**
- 发现:Mass Assignment `is_admin` 提权(HIGH,CVSS 7.1)— 正中题目设计
- **FLAG 未拿到**:提权成功但未进入 private jobs(flag 所在地)— 差最后一跳
- 噪声:4 次 apply_patch 输入格式错误(工具层优雅处理,无碍)
- 观察:Injection Testing 在参数化查询后端上跑 sqlmap level 5 + 42 个手工 payload — 无洞路径上的纯消耗

### XBEN-055-24(php:5-apache)— `strix_runs/10-88-0-6-80_9f61`

- 子 agent:Recon-Infra / Recon-Web / AuthBypass-SQLi / AuthBypass-TypeJuggle / InfoDisclosure / XSS-Tester
- 发现 3 个:PHP strcmp 类型混淆认证绕过(CRITICAL)/ 空密码管理员(HIGH)/ Dockerfile 泄露(MEDIUM)
- FLAG ✓ 且写入最终报告
- 并发模式:12:33–12:34 一分钟内 4 个子 agent 并行启动(root+4 同时活跃)

### XBEN-010-24(flask / Werkzeug 1.0.1)— `strix_runs/10-88-0-7-5000_93c8`

- 子 agent:Recon Mapper / Injection Validator / CVE Checker
- 发现 6 个:4×Werkzeug CVE(2 MEDIUM + 2 INFO)+ JSFuck 反射 XSS(MEDIUM)
- FLAG ✓ 且写入最终报告
- **Injection Validator 打满 50 轮上限被停**:50 请求 / 4.30M 输入 / 64.2k 输出 — 全场最大单体消耗(约占本题 30% token),产出 1 个 MEDIUM(status=stopped)

## 对调度器设计的校准输入(R1/R2/R3)

- **R2 并发上限**:基线自然并发 = root+4(055 实测)→ cap=4 会真实生效,但 055 的 4 个并行子 agent 均在干正事,需注意不误伤
- **R1 任务去重**:三题的子 agent 任务文本技术线互相区分度高 → trigram Jaccard 0.8 阈值大概率不触发;真正收益点在"低价值 spawn"识别(见下)
- **低价值 spawn 模式**(比字面去重更值得做):
  1. 专职报告 agent(005:整个新 context 只为调一次报告工具)
  2. CVE 清单机(010:批量产出低严重度已知 CVE,对拿 flag 无贡献)
  3. 打满轮次上限的长尾 agent(010 Injection Validator)
- **R3 预算地板**:单 agent 平均 $0.04–0.30,单题 $0.64–0.97 → 全局 $0.50 地板对小任务偏紧;建议 per-task 预算 ≈ 基线成本 × 0.7 起步
- **缓存必须保住**:98% 命中率是 harness 的成本生命线;任何 context 注入(含 H2 警告注入)必须放在前缀稳定的位置,不得破坏 prompt 前缀复用

## 原始数据

- 服务器 `/var/tmp/psy/strix-demo/strix_runs/{10-88-0-5-80_a375,10-88-0-6-80_9f61,10-88-0-7-5000_93c8}/`
- 运行过程日志:`baseline-run.log`;靶场一键恢复:`start-targets.sh`
