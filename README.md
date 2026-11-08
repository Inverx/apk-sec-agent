# APK 安全分析与代码审计工程
APK-SecAgent · Android Static Security Analysis & Code Audit Platform

面向 Android 应用包（APK）的静态安全分析、反编译源码检索与自动化代码审计工程实现。

## 项目简介

本项目面向 Android 客户端应用包分析场景，主要用于 APK 逆向拆解、静态安全规则扫描、通信加解密调用链追踪及相关工程化研究。

通过对目标应用包的：

```text
分片上传与归档完整性校验
    +
DEX / Manifest 静态反编译
    +
多维静态安全规则扫描
    +
类与方法边界切块及混合索引
    +
MCP 代码审计工具链与流式追踪
```

将传统手工逆向分析中高频重复的「解包反编译 → Manifest 组件排查 → 硬编码密钥与密码学误用扫描 → 签名加解密交叉引用追踪」流程拆解并固化为可独立部署、便于维护和扩展的工程套件。

项目主要由三部分组成：

```text
Backend & Static Analyzer (FastAPI 异步服务与静态扫描管线)
    +
JADX Code MCP & Hybrid RAG (代码检索与 MCP 审计工具服务)
    +
Audit Workbench Frontend (Vue 3 风险看板、源码浏览与交互分析台)
```

各子系统通过明确的数据结构与接口边界解耦，既可作为完整 Web 工作台运行，也可单独挂载 `mcp_server/` 作为标准 MCP 工具服务供本地分析环境调用。

## 项目结构

```text
apk-sec-agent/
│
├── backend/
│   ├── app/
│   │   ├── api/              # REST 与 SSE 路由层 (auth / apks / tasks / agent)
│   │   ├── config.py         # 环境配置与运行参数定义
│   │   ├── database.py       # SQLAlchemy 2.0 会话与连接管理
│   │   ├── main.py           # 应用入口与生命周期编排
│   │   ├── middleware.py     # 纯 ASGI 限流、请求追踪、异常信封与日志脱敏
│   │   ├── models.py         # ORM 实体模型 (User / ApkFile / UploadSession / Task / Finding)
│   │   ├── schemas.py        # Pydantic v2 请求与响应契约
│   │   └── security.py       # bcrypt 密码哈希与 JWT 令牌签发校验
│   │
│   ├── services/
│   │   ├── storage.py        # 分片写入、SHA256 秒传幂等与双层 Zip Slip 校验
│   │   ├── task_queue.py     # CAS 乐观锁异步状态机、超时控制与指数退避重试
│   │   ├── pipeline.py       # 反编译、静态扫描与代码索引阶段编排
│   │   └── report.py         # Markdown / JSON 结构化审计报告导出
│   │
│   ├── analyzer/
│   │   ├── decompiler.py     # JADX / Apktool / 内置解析器三级回退调度
│   │   ├── manifest.py       # AndroidManifest.xml 权限、入口与导出组件解析
│   │   ├── scanner.py        # 静态扫描规则注册与汇总调度
│   │   └── rules/            # 6 类静态检测规则实现 (Manifest / 网络 / 密钥 / 密码学 / 加固 / WebView)
│   │
│   ├── agent/
│   │   ├── chunker.py        # Java 类与方法边界切块器 (花括号深度状态机)
│   │   ├── rag.py            # 驼峰分词、Okapi BM25、特征哈希向量与 RRF 重排
│   │   ├── guardrails.py     # 不可信样本代码边界隔离与提示词注入检测
│   │   ├── llm.py            # OpenAI 兼容接口客户端封装
│   │   └── react.py          # 工具编排与 SSE 流式审计链路
│   │
│   ├── Dockerfile
│   └── requirements.txt      # Python 环境依赖说明
│
├── mcp_server/
│   └── jadx_code_mcp.py      # 独立 JADX 代码审计 MCP Server (支持进程内与 stdio JSON-RPC)
│
├── frontend/
│   ├── src/
│   │   ├── views/            # 登录、任务上传、风险看板、源码浏览器、交互分析视图
│   │   ├── components/       # 布局外壳、风险列表、等级徽标与状态指示组件
│   │   ├── stores/           # 登录态与角色权限管理
│   │   ├── api.ts            # REST 请求封装与 Fetch ReadableStream SSE 解析
│   │   ├── sha256.ts         # 客户端流式增量 SHA-256 计算
│   │   └── markdown.ts       # 审计报告与代码片段渲染
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
│
├── scripts/
│   ├── generate_sample_apk.py # 合成测试样本 APK 生成脚本
│   └── benchmark.py           # 接口并发延迟与吞吐测试脚本
│
├── tests/                     # pytest 自动化回归测试套件 (80 项测试)
├── docker-compose.yml
├── pytest.ini
├── start-dev.ps1
├── LICENSE
└── README.md
```

## 功能

目前项目涉及的主要模块与能力包括：

### 1. 后端服务与静态分析引擎 (`backend/`)

| 模块 / 文件 | 功能 |
|---|---|
| `services/storage.py` | 分片上传（`init` / `chunk` / `complete`）、全文 SHA-256 内容寻址秒传幂等、ZIP 魔数校验及双层 Zip Slip 路径穿越拦截 |
| `services/task_queue.py` | 基于 SQL 条件更新乐观锁（CAS）的异步任务状态机，支持跨阶段超时预算共享、指数退避重试与异常中断任务恢复 |
| `analyzer/decompiler.py` | 反编译调度器，按 `JADX CLI → Apktool → 内置轻量解析器` 三级回退提取 `AndroidManifest.xml` 与反编译源码树 |
| `analyzer/manifest.py` | 提取应用包名、版本、权限清单、入口 Activity 及导出组件（Activity / Service / Receiver / Provider） |
| `analyzer/rules/` | 6 类 10 条静态安全检测规则，输出严重等级（`CRITICAL` ~ `LOW`）、CWE 编号、文件路径、行号与修复建议 |
| `services/report.py` | 按任务导出包含基本信息、加固特征、Manifest 组件表与风险代码片段的 Markdown / JSON 报告 |
| `app/middleware.py` | 纯 ASGI 滑动窗口限流、请求耗时追踪（`X-Request-ID`）、敏感凭据日志脱敏过滤与统一异常响应信封 |

### 2. MCP 代码审计工具与混合检索 (`mcp_server/` & `backend/agent/`)

| 模块 / 文件 | 功能 |
|---|---|
| `jadx_code_mcp.py` | 封装包类枚举、关键词正则搜索、类源码按行读取、方法/常量交叉引用查找、Manifest 读取 5 个只读审计工具 |
| `agent/chunker.py` | 按 Java 包、类与方法边界切分反编译源码，保留包名、类名、方法签名与起止行号元数据 |
| `agent/rag.py` | 结合驼峰/下划线双粒度分词，实现 `Okapi BM25 + 512 维特征哈希向量 + RRF (k=60)` 混合检索重排 |
| `agent/guardrails.py` | 针对不可信反编译源码的三层边界防护（9 类注入模式行号扫描、`<untrusted_decompiled_code>` 标签隔离、输出校验） |
| `agent/react.py` | 支持 OpenAI 兼容 Tool Calling 与内置确定性编排双模式，通过 SSE 流式输出工具调用与签名加密链路还原结论 |

### 3. 前端审计工作台 (`frontend/`)

| 模块 / 文件 | 功能 |
|---|---|
| `views/TasksView.vue` | 拖拽分片上传、客户端增量 SHA-256 秒传预检、任务状态轮询与失败任务重试 |
| `views/DashboardView.vue` | 风险类别与严重度堆叠分布图、CWE Top 统计、加固识别状态、Manifest 导出组件清单与报告下载 |
| `views/CodeBrowserView.vue` | 反编译包/类目录树、带行号与语法高亮的源码视图、跨文件全文搜索及风险项精确跳行定位 |
| `views/AgentChatView.vue` | 流式展示代码检索、MCP 工具调用参数、数据边界隔离提示与最终审计证据链 |

具体文件及参数定义请以对应目录中的代码为准。

## 设计思路

项目并不是把反编译文本直接整段拼接进提示词，而是将文件校验、异步分析管线、代码结构化索引与受控工具调用拆分为分层架构：

```text
                       Vue 3 Audit Workbench / REST Client
                                        │
                                        ▼
                         FastAPI Gateway & Pure ASGI Layer
                     (JWT · RBAC · RateLimit · SecretMasking)
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
            ▼                           ▼                           ▼
   Chunked Upload & CAS        Async Task Pipeline         ReAct Audit Engine
 (SHA256 / ZipSlip Guard)   (Optimistic State Machine)   (SSE Stream / Guardrails)
                                        │                           │
                        ┌───────────────┼───────────────┐           ├───────────────┐
                        │               │               │           │               │
                        ▼               ▼               ▼           ▼               ▼
                   Decompiler     Static Scanner   Code Chunker  Hybrid RAG   JADX MCP Server
                 (JADX/Apktool)   (6 Rule Suites)  (Class/Method) (BM25+RRF)  (5 Read-Only Tools)
```

接口层只处理认证鉴权、参数校验与流式传输，底层分析管线按固定状态机推进：

```text
1. 分片接收与归档安全校验 (PENDING)
    ↓
2. DEX 与 Manifest 反编译提取 (DECOMPILING)
    ↓
3. 6 类静态规则扫描与加固识别 (SCANNING)
    ↓
4. 类/方法边界切块与混合索引构建 (INDEXING)
    ↓
5. 审计看板就绪与 MCP 工具链挂载 (COMPLETED)
```

相同 SHA-256 的样本在 `init` 或 `complete` 阶段命中已完成任务时直接复用历史结果，避免重复反编译开销。

## 静态扫描与规则体系

静态扫描引擎针对反编译产物中的高频客户端安全缺陷内置 6 类检测规则：

```text
Static Rule Engine
    ├── Manifest 配置风险 (MANIFEST-001 ~ 003)
    │     ├── android:debuggable="true" 调试开启
    │     ├── android:allowBackup="true" 任意数据备份
    │     └── 无权限保护的导出组件 (Exported Activity / Service / Receiver / Provider)
    │
    ├── 网络通信安全 (NET-001 ~ 002)
    │     ├── 明文 HTTP URL 与 cleartextTrafficPermitted
    │     └── 自定义 X509TrustManager / HostnameVerifier 忽略证书校验
    │
    ├── 硬编码敏感凭据 (SECRET-001)
    │     └── AK/SK、JWT Secret、PEM 私钥与高熵密钥常量
    │
    ├── 密码学误用 (CRYPTO-001 ~ 004)
    │     ├── AES/ECB 不安全分组模式
    │     ├── 硬编码静态 IvParameterSpec
    │     ├── MD5 / SHA-1 弱哈希签名算法
    │     └── 硬编码字面量构造 SecretKeySpec
    │
    ├── 加固壳特征识别 (PACKER-001)
    │     └── 360 加固、梆梆、爱加密、腾讯乐固、网易易盾 SO 与入口类特征匹配
    │
    └── WebView 组件风险 (WEBVIEW-001)
          └── setJavaScriptEnabled(true) 配合 addJavascriptInterface 桥接暴露
```

每条命中结果均关联对应的 CWE 编号、源码相对路径、精确行号、上下文代码片段与修复建议。

## 代码检索与数据边界隔离

在追踪客户端 `tokenSign` 加盐签名、会话密钥派生或请求载荷加密逻辑时，单纯依赖文件名或固定长度文本切块容易丢失上下文。本项目通过以下流程组织代码检索与安全隔离：

```text
Decompiled Java Sources (.java)
    │
    ▼
Class & Method Boundary Chunker (花括号深度追踪 + 行号元数据保留)
    │
    ├──► CamelCase / Snake_case Tokenizer ──► Okapi BM25 Index (精确符号与常量匹配)
    │                                                  │
    └──► 512-dim Feature Hashing Embedder ──► Cosine Vector Search (自然语言语义匹配)
                                                       │
                                                       ▼
                                        Reciprocal Rank Fusion (RRF, k=60)
                                                       │
                                                       ▼
                                    <untrusted_decompiled_code> 数据边界封装
```

由于待分析的 APK 属于外部不可信输入，样本注释或字符串常量中可能包含诱导性指令（Indirect Prompt Injection）。因此所有反编译源码在进入分析上下文前均经过三层处理：

```text
1. 输入扫描 (Input Pattern Scan)
   检测反编译代码与注释中的指令覆盖、系统提示词套取与标签伪造特征并记录行号
    +
2. 边界隔离 (Untrusted Data Boundary)
   使用 <untrusted_decompiled_code> 标签包裹全部源码片段，声明标签内容仅作待审样本数据
    +
3. 输出校验 (Output Validation)
   执行 8-gram 系统提示词重叠检测与风险结论一致性校验
```

## 环境

推荐环境：

- Python 3.11+
- Node.js 20+
- Windows / Linux / macOS

可选外部逆向工具（未安装时自动回退至内置解析器）：

- JADX (`jadx` / `JADX-CLI`)
- Apktool (`apktool`)

## 快速开始

### 1. Clone

```bash
git clone https://github.com/Inverx/apk-sec-agent.git
cd apk-sec-agent
```

### 2. 启动后端服务与生成测试样本

创建虚拟环境并安装依赖：

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt
```

生成合成测试样本 APK（含加盐签名、AES-CBC 加密、硬编码密钥、明文 HTTP、导出组件与恶意注释样本）：

```bash
.venv/Scripts/python scripts/generate_sample_apk.py
```

启动 FastAPI 服务（默认监听 `127.0.0.1:8000`）：

```bash
.venv/Scripts/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

### 3. 启动前端工作台

另开终端进入 `frontend/` 目录：

```bash
cd frontend
npm install
npm run dev
```

浏览器访问 `http://localhost:5173`。首次启动默认初始化以下本地测试账号：

| 角色 | 账号 | 密码 | 权限范围 |
|---|---|---|---|
| `admin` | `admin` | `Admin@12345` | 全部权限、用户角色管理、失败任务重试 |
| `analyst` | `analyst` | `Analyst@12345` | 上传样本、导出审计报告、发起流式代码分析 |
| `viewer` | `viewer` | `Viewer@12345` | 只读查看风险看板、反编译源码与历史分析记录 |

Windows 环境下也可直接运行根目录脚本一键拉起前后端：

```powershell
powershell -ExecutionPolicy Bypass -File start-dev.ps1
```

### 4. 独立运行 JADX MCP Server

`mcp_server/jadx_code_mcp.py` 支持作为标准 `stdio` JSON-RPC 2.0 服务独立运行，可挂载至支持 MCP 协议的客户端：

```bash
.venv/Scripts/python -m mcp_server.jadx_code_mcp --workspace <反编译工作区目录>
```

暴露的 5 个工具：

- `list_packages_and_classes`
- `search_code_by_keyword`
- `get_class_source`
- `find_xrefs`
- `get_manifest_info`

### 5. 运行自动化测试与基准压测

运行 `pytest` 测试套件（80 项测试，覆盖认证鉴权、分片秒传、Zip Slip 防御、状态机重试、6 类扫描规则、MCP 协议、混合检索与三层注入边界）：

```bash
.venv/Scripts/python -m pytest tests/ --cov=backend --cov=mcp_server --cov-report=term
```

运行并发基准测试脚本：

```bash
.venv/Scripts/python scripts/benchmark.py --users 32 --duration 10
```

### 6. Docker Compose 部署

```bash
docker compose up --build
```

## 接口概览

| 方法 | 路径 | 说明 | 最低角色 |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` / `/login` | 账号注册与登录签发 JWT | 公开 |
| `GET` | `/api/v1/auth/me` | 查询当前登录用户信息 | `viewer` |
| `PATCH` | `/api/v1/auth/users/{id}/role` | 修改用户角色权限 | `admin` |
| `POST` | `/api/v1/apks/upload/init` | 初始化上传会话与 SHA-256 秒传预检 | `analyst` |
| `POST` | `/api/v1/apks/upload/chunk` | 上传单个文件分片 | `analyst` |
| `POST` | `/api/v1/apks/upload/complete` | 合并校验分片并投递异步分析任务 | `analyst` |
| `GET` | `/api/v1/tasks` / `/tasks/{id}` | 查询任务列表、状态与统计摘要 | `viewer` |
| `GET` | `/api/v1/tasks/{id}/findings` | 按严重等级或类别筛选静态扫描结果 | `viewer` |
| `GET` | `/api/v1/tasks/{id}/report.md` / `.json` | 导出 Markdown 或 JSON 审计报告 | `analyst` |
| `GET` | `/api/v1/tasks/{id}/code/tree` / `/file` / `/search` | 浏览反编译文件树、读取源码与关键词搜索 | `viewer` |
| `GET` | `/api/v1/tasks/{id}/rag/search` | 执行 BM25 + 向量 + RRF 混合代码检索 | `viewer` |
| `GET` | `/api/v1/tasks/{id}/agent/stream` | 发起流式代码审计问答（SSE） | `analyst` |
| `GET` | `/api/v1/tasks/{id}/agent/messages` | 获取任务历史审计对话与步骤记录 | `viewer` |
| `POST` | `/api/v1/tasks/{id}/retry` | 重置并重新投递失败任务 | `admin` |
| `GET` | `/health` | 服务与异步 Worker 健康状态检查 | 公开 |

## 隐私与数据安全

请 **不要** 将受版权保护的商业应用安装包、真实生产密钥或个人敏感信息提交到公开仓库。

包括但不限于：

```text
未授权的第三方商业 APK 原包
真实业务环境 API Key / AccessKey / SecretKey
真实服务器私钥与证书文件
包含个人身份或认证凭据的抓包与调试日志
.env 环境配置文件与运行期 SQLite 数据库文件 (data/)
```

仓库中的 `scripts/generate_sample_apk.py` 仅生成合成测试样本用于验证扫描规则与检索链路。运行期上传的样本、反编译产物与数据库默认保存在本地 `data/` 目录下（已由 `.gitignore` 排除）。

## Issue / Pull Request

欢迎提交：

```text
Bug Report
Static Rule Enhancement
Decompiler Compatibility
Code Chunker & Retrieval Improvement
Documentation
```

提交 Issue 时建议至少提供：

- Python Version
- Node.js Version
- Operating System
- Error Message / Traceback
- Minimal Reproduction

## Research & Disclaimer

本项目主要用于：

- Android Application Security Auditing
- Static Code Analysis & Rule Engineering
- Decompiled Code Indexing & Hybrid Retrieval Research
- MCP Tooling & Indirect Prompt Injection Defense Research

以及本人设备、合成测试样本或获得明确授权环境中的安全研究与工程学习。

请遵守所在地法律法规及目标软件的授权范围，请勿将本项目用于未经授权的逆向篡改、商业软件破解或其他侵犯第三方合法权益的行为。使用者应自行承担因使用、修改或分发本项目所产生的责任。

## License

本项目基于 MIT License 开源。

详见：

[LICENSE](LICENSE)
