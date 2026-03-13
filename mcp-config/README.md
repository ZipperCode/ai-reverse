# MCP Server 配置说明

本文件说明 `claude-code-mcp.json` 和 `codex-config.toml` 中各 MCP Server 的配置方式。

## Frida MCP Server

- **功能**: 动态 Hook、进程注入、运行时分析
- **安装**: `pip install frida-mcp`
- **前置条件**: Android 设备已连接且运行 frida-server
- **命令**: `frida-mcp`

## jadx MCP Server

- **功能**: Java 反编译、源码搜索、交叉引用 (24+ tools)
- **来源**: [github.com/zinja-coder/jadx-mcp-server](https://github.com/zinja-coder/jadx-mcp-server)
- **前置条件**: Java 11+
- **命令**: `python3 <path>/jadx_mcp_server.py`
- **注意**: 路径需替换为实际的 jadx-mcp-server 安装目录（setup.sh 自动处理）

## apktool MCP Server

- **功能**: Smali 反编译、资源分析、Manifest 解析 (12 tools)
- **来源**: [github.com/zinja-coder/apktool-mcp-server](https://github.com/zinja-coder/apktool-mcp-server)
- **前置条件**: Java 11+, uv
- **命令**: `uv --directory <path> run apktool_mcp_server.py`
- **注意**: 路径需替换为实际的 apktool-mcp-server 安装目录（setup.sh 自动处理）

## [可选] JSHook MCP Server

- **功能**: JavaScript Hook、浏览器调试 (245 tools)
- **来源**: [github.com/vmoranv/jshookmcp](https://github.com/vmoranv/jshookmcp)
- **命令**: `node <path>/index.js`
- **说明**: Web/JS 逆向用，Android 逆向暂不需要

## 配置文件位置

| 工具 | 配置文件路径 |
|------|-------------|
| Claude Code (项目级) | 项目根目录 `.mcp.json` |
| Claude Code (全局) | `~/.claude/mcp.json` |
| Codex CLI | `~/.codex/config.toml` |

## 使用 setup.sh 自动配置

运行 `bash scripts/setup.sh` 会自动从 `.mcp.json.template` 生成 `.mcp.json`，将路径占位符替换为实际绝对路径。
