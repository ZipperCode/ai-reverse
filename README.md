# AI-Reverse

AI 驱动的 Android 逆向工程工具框架，通过 MCP 协议将静态分析（jadx、apktool）与动态分析（Frida）串联，在 Claude Code / Codex 中实现 API 提取、APK 脱壳、算法还原的一站式工作流。

## 架构

```
┌─────────────────────────────────────────────────┐
│              Claude Code / Codex CLI             │
│                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│   │ SKILL.md │  │ CLAUDE.md│  │ Frida Scripts │  │
│   └────┬─────┘  └──────────┘  └───────┬──────┘  │
│        │            MCP 协议           │         │
│   ┌────▼────────────────────────────────▼────┐   │
│   │                                          │   │
│   │  ┌──────────┐ ┌─────────┐ ┌───────────┐ │   │
│   │  │ jadx-mcp │ │apktool- │ │ frida-mcp │ │   │
│   │  │ (反编译) │ │  mcp    │ │ (动态Hook)│ │   │
│   │  │ 24+tools │ │(资源)   │ │           │ │   │
│   │  └──────────┘ │ 12tools │ └───────────┘ │   │
│   │               └─────────┘                │   │
│   └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │  Android Device  │
              │  (frida-server)  │
              └─────────────────┘
```

## 快速开始

> 详细使用指南请参考 [docs/usage-guide.md](docs/usage-guide.md)，涵盖环境搭建、设备配置、frida-server 部署、脚本参数说明和常见问题排查。

### 1. 安装环境

```bash
# 前置依赖: Python 3, Java 11+, ADB, uv, Git
bash scripts/setup.sh
```

### 2. 准备设备

```bash
# 确认设备连接
adb devices

# 推送并启动 frida-server (设备需 root)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# 验证
frida-ps -U
```

### 3. 使用 Skill

在 Claude Code 中打开项目目录，使用自然语言描述逆向目标：

```
帮我分析这个 APK 的所有 API 接口: target.apk
```

或使用 Skill 触发完整工作流：

```
/android-re
```

## 工作流

### 1. 静态分析
jadx 反编译 APK → 解析 Manifest → 浏览类结构 → 关键字搜索 → 源码分析 → 交叉引用

### 2. 动态分析
frida spawn 目标 → 注入 Hook 脚本 → 操作应用 → 收集运行时数据

### 3. API 提取
静态搜索 Retrofit/OkHttp 注解 + 动态 trace-api.js 抓包 → API 文档

### 4. APK 脱壳
检测加固 → frida spawn → dump-dex.js 内存 dump → jadx 分析

### 5. 算法还原
jadx 定位加密代码 → 分析数据流 → hook-crypto.js 捕获参数 → Python 复现

### 6. 全流程
脱壳 → 静态分析 → 定位目标 → 动态 Hook → 文档输出

## Frida 脚本

| 脚本 | 用途 | 独立使用 |
|------|------|---------|
| `dump-dex.js` | DEX 内存 dump (脱壳) | `frida -U -f <包名> -l scripts/frida-scripts/dump-dex.js` |
| `ssl-unpin.js` | SSL Pinning 通杀绕过 | `frida -U -f <包名> -l scripts/frida-scripts/ssl-unpin.js` |
| `hook-crypto.js` | 加密函数 Hook | `frida -U -f <包名> -l scripts/frida-scripts/hook-crypto.js` |
| `trace-api.js` | HTTP API 追踪 | `frida -U -f <包名> -l scripts/frida-scripts/trace-api.js` |

### 多脚本组合

```bash
# 绕过 SSL + 追踪 API
frida -U -f com.target.app -l scripts/frida-scripts/ssl-unpin.js -l scripts/frida-scripts/trace-api.js

# 绕过 SSL + Hook 加密
frida -U -f com.target.app -l scripts/frida-scripts/ssl-unpin.js -l scripts/frida-scripts/hook-crypto.js
```

## 项目结构

```
ai-reverse/
├── .mcp.json                    # MCP Server 配置
├── CLAUDE.md                    # 项目级 AI 指令
├── skills/android-re/
│   ├── SKILL.md                 # 主 Skill (5大工作流)
│   └── references/
│       ├── api-extraction.md    # API 提取指南
│       ├── unpacking.md         # 脱壳方案指南
│       └── algorithm-restore.md # 算法还原指南
├── scripts/
│   ├── setup.sh                 # 环境安装脚本
│   └── frida-scripts/           # Frida 脚本
├── mcp-config/                  # MCP 配置参考
├── templates/                   # 输出文档模板
└── output/                      # 分析产出
```

## MCP 配置

### Claude Code

`setup.sh` 会自动配置 `.mcp.json`。也可参考 `mcp-config/claude-code-mcp.json` 手动配置。

### Codex CLI

参考 `mcp-config/codex-config.toml` 配置 `~/.codex/config.toml`。

## 依赖

- **Python 3.8+**
- **Java 11+** (jadx / apktool)
- **ADB** (Android 调试桥)
- **uv** (Python 包管理)
- **Frida** (`pip install frida-mcp frida-tools`)
- **Root Android 设备或模拟器** (运行 frida-server)
