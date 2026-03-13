# AI-Reverse: Android 逆向工程框架

## 项目定位

AI 驱动的 Android 逆向工程工具框架，通过 MCP 协议串联静态分析与动态分析，在 Claude Code / Codex 中实现一站式逆向工作流。

## 可用 MCP Server

| Server | 用途 | 工具数 |
|--------|------|--------|
| `jadx` | Java 反编译、源码搜索、交叉引用 | 24+ |
| `apktool` | Smali 反编译、资源分析、Manifest 解析 | 12 |
| `frida` | 动态 Hook、进程注入、运行时分析 | 多种 |

## 核心工作流

### 1. 静态分析
jadx-mcp 打开 APK → 解析 Manifest → 浏览类列表 → 关键字搜索 → 阅读源码 → 交叉引用追踪

### 2. 动态分析
frida-mcp spawn/attach 目标进程 → 注入 Frida 脚本 → 实时收集数据

### 3. API 提取
静态搜索 Retrofit/OkHttp 注解 + 动态注入 `trace-api.js` → 输出 API 文档
- 详细指南: `skills/android-re/references/api-extraction.md`

### 4. APK 脱壳
检测加固方案 → frida spawn → 注入 `dump-dex.js` → jadx 分析 dump 出的 DEX
- 详细指南: `skills/android-re/references/unpacking.md`

### 5. 算法还原
jadx 定位加密代码 → 分析数据流 → 注入 `hook-crypto.js` 捕获参数 → Python 复现验证
- 详细指南: `skills/android-re/references/algorithm-restore.md`

### 6. 全流程编排
脱壳 → 静态分析 → 定位目标功能 → 动态 Hook 验证 → 文档输出

## Frida 脚本

| 脚本 | 路径 | 用途 |
|------|------|------|
| DEX Dump | `scripts/frida-scripts/dump-dex.js` | 内存 dump DEX（脱壳） |
| SSL Unpin | `scripts/frida-scripts/ssl-unpin.js` | SSL Pinning 通杀绕过 |
| Hook Crypto | `scripts/frida-scripts/hook-crypto.js` | 加密函数 Hook（算法还原） |
| Trace API | `scripts/frida-scripts/trace-api.js` | HTTP API 调用追踪 |

## 输出规范

- 使用 `templates/` 中的模板格式化输出
- 所有分析产出保存到 `output/` 目录
- API 文档使用 `templates/api-doc-template.md` 格式
- 算法文档使用 `templates/algorithm-doc-template.md` 格式

## 语言偏好

始终使用中文回复。
