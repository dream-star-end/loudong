# VulnHunter — PRD 完整实现任务清单

> 基于 `VulnHunter_PRD_v2.docx` 逐项对照，从架构骨架推进到全功能 MVP-1。

---

## Phase 1: 核心基础设施（PRD §4/§5）

### T1 — LLM 集成层
- [ ] `vulnhunter/llm/client.py` — 统一 LLM 客户端（OpenAI / Claude）
- [ ] 规则引擎 fallback：无 API Key 时退化为确定性规则分析
- [ ] Agent base 类集成 `llm_client`，支持 ReAct 推理循环
- **对应 PRD**: §1.4 "LLM 只决策不执行"、§10 模型层

### T2 — Engagement Manifest
- [ ] `vulnhunter/core/manifest.py` — 解析 `engagement_manifest.yaml`
- [ ] Scope 配置：target.hosts / allow_login / allow_state_change / depth / standards
- [ ] 角色与凭据管理
- **对应 PRD**: §5.3 Scope 配置示例

### T3 — Rate Limiter
- [ ] `vulnhunter/core/rate_limiter.py` — 令牌桶算法
- [ ] 全局 10 QPS 默认限速，单工具可配
- [ ] 与 HTTP Tool / Browser Tool 集成
- **对应 PRD**: §5.2 第 4 条 "默认低速率"

### T4 — 持久化审计日志
- [ ] `AuditLog` 数据模型 + DB 表
- [ ] 中间件：每个工具调用自动记录（请求/响应/时间/Agent/风险等级）
- [ ] API 端点：查询审计日志
- **对应 PRD**: §5.2 第 7 条 "全链路审计"

### T5 — L0-L3 动作分级
- [ ] `vulnhunter/core/action_classifier.py` — 动作风险分级引擎
- [ ] L0(只读) 自动执行 / L1(低风险) 限速执行 / L2(中风险) 需审批 / L3(高风险) 默认禁用
- [ ] 与 Scope Guard 联动
- **对应 PRD**: §5.1 动作分级

---

## Phase 2: Agent 真实实现（PRD §3 / §9.1 MVP-1）

### T6 — Recon Agent（信息收集）
- [ ] 真实 HTTP 请求：分析响应头（HSTS/CSP/X-Frame/Server/X-Powered-By）
- [ ] 技术栈指纹识别（框架/服务器/CMS 特征）
- [ ] robots.txt / sitemap.xml 解析
- [ ] OpenAPI/Swagger 自动发现
- [ ] 输出：`asset_inventory` + `route_map` + `entry_points`
- **对应 PRD**: §3.2 WSTG-INFO-*

### T7 — Crawl Agent（页面/状态发现）
- [ ] Playwright 驱动浏览器真实遍历页面
- [ ] 提取所有链接、表单、API 调用
- [ ] 构建 page_graph（页面→接口→操作 关联图）
- [ ] 生成 HAR 流量包
- [ ] 输出：`page_graph` + `route_list` + `request_templates`
- **对应 PRD**: §3.3 / MVP-1 "登录+浏览器遍历" "抓包+路由提取" "页面/API图谱构建"

### T8 — AuthZ Agent（认证授权）
- [ ] Cookie 安全分析（Secure/HttpOnly/SameSite/Expires）
- [ ] JWT 解析与安全检查（算法/过期/签名强度）
- [ ] 多角色访问对比（同一资源不同角色返回差异）
- [ ] IDOR 检测（对象 ID 可预测性 + 越权访问）
- [ ] 会话固定/会话劫持检查
- **对应 PRD**: §3.4 WSTG-ATHN/ATHZ/SESS

### T9 — Input Agent（输入验证）
- [ ] 自动发现所有输入点（query/body/header/cookie/path）
- [ ] 参数画像：类型推断 + 约束识别
- [ ] XSS 反射探测（安全探针，非破坏性）
- [ ] SQL 注入基础探测（错误触发，非数据提取）
- [ ] 异常响应聚类分析
- **对应 PRD**: §3.5 WSTG-INPV-*

### T10 — BizLogic Agent（业务逻辑）
- [ ] 从 Crawl 结果学习业务流程
- [ ] 流程跳步检测
- [ ] 频率/次数限制检查
- [ ] 状态完整性校验
- **对应 PRD**: §3.6 WSTG-BUSL-*

### T11 — Evidence Agent（证据与报告）
- [ ] Finding 去重（相同类别+同一端点合并）
- [ ] 交叉验证：多 Agent 结果关联
- [ ] 置信度评分（基于证据数量 + 可复现性）
- [ ] WSTG / ASVS / OWASP Top 10 标准映射
- **对应 PRD**: §3.7 / §7.1 误报治理

---

## Phase 3: 平台能力（PRD §4/§5/§6）

### T12 — MinIO 证据归档
- [ ] ArtifactStore 接入 MinIO（替代本地文件系统）
- [ ] 截图、HAR、请求/响应原文、DOM Snapshot 上传
- [ ] Evidence 记录关联 MinIO 对象 URL
- **对应 PRD**: §4.2 Artifact Tool / §5.2 第 8 条 "证据留存"

### T13 — HITL 人工审批
- [ ] 审批队列模型（PendingApproval）
- [ ] L2/L3 动作自动暂停，等待审批
- [ ] API 端点：列出待审批 / 批准 / 拒绝
- [ ] 前端审批面板
- **对应 PRD**: §5.2 第 6 条 "高风险动作审批"

### T14 — 三层记忆体系
- [ ] Redis 短期记忆：当前扫描状态、最近操作、会话缓存
- [ ] PostgreSQL 任务级记忆：路由清单、请求样本、已确认项
- [ ] 长期知识库：WSTG 模板、框架特征库、误报规则（JSON/PG）
- **对应 PRD**: §6.1

### T15 — 4 层误报治理
- [ ] 语义校验：分析响应内容是否真正泄露了不该有的数据
- [ ] 多角色对照：同一请求不同角色响应 diff
- [ ] 多证据合并：至少两项证据才确认
- [ ] 重试一致性：同类测试重复两次确认可复现
- **对应 PRD**: §7.1

---

## Phase 4: 输出与集成

### T16 — 报告生成
- [ ] HTML 开发报告：按 WSTG/ASVS/Top10 组织，含修复建议
- [ ] Agent 自省报告：token 消耗、工具调用次数、覆盖率
- [ ] 报告下载 API + 前端下载按钮
- **对应 PRD**: §3.7 输出层 / §11 评估指标

### T17 — 真实扫描流水线
- [ ] 替换 scan_simulator，用真实 Agent 链驱动扫描
- [ ] Orchestrator 解析 manifest → 分发任务 → 收集结果 → Evidence 汇总
- [ ] P0→P6 执行阶段状态机
- [ ] 前端实时进度展示
- **对应 PRD**: §7 执行流程

---

## Phase 5: 质量保障

### T18 — 测试 & 验证
- [ ] 所有新组件单元测试
- [ ] 集成测试：完整扫描流程
- [ ] ruff lint 通过
- [ ] 前端全流程演示
- **对应 PRD**: §11 评估指标
