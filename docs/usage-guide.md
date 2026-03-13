# AI-Reverse 使用指南

本文档是 AI-Reverse 框架的完整使用手册，从环境搭建到实战操作，帮助你快速上手 Android 逆向分析。

---

## 目录

1. [环境准备](#1-环境准备)
2. [设备配置](#2-设备配置)
3. [安装与配置](#3-安装与配置)
4. [在 Claude Code 中使用](#4-在-claude-code-中使用)
5. [独立使用 Frida 脚本](#5-独立使用-frida-脚本)
6. [工作流详解](#6-工作流详解)
7. [Frida 脚本参数详解](#7-frida-脚本参数详解)
8. [常见问题排查](#8-常见问题排查)
9. [进阶技巧](#9-进阶技巧)

---

## 1. 环境准备

### 1.1 必需软件

| 软件 | 最低版本 | 用途 | 安装方式 |
|------|---------|------|---------|
| Python 3 | 3.8+ | MCP Server 运行 | `brew install python3` (macOS) / `apt install python3` (Linux) |
| Java | 11+ | jadx / apktool 运行 | `brew install openjdk@17` / `apt install openjdk-17-jdk` |
| ADB | 最新版 | 连接 Android 设备 | `brew install android-platform-tools` / `apt install adb` |
| uv | 最新版 | Python 包管理 | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Git | 2.0+ | 克隆依赖仓库 | `brew install git` / `apt install git` |
| pip3 | 随 Python | 安装 Frida | 随 Python 安装 |

### 1.2 Frida 版本匹配

**Frida 的客户端 (frida-tools) 和服务端 (frida-server) 版本必须完全一致。**

```bash
# 查看本机 frida 版本
frida --version
# 输出示例: 16.2.1

# 下载对应版本的 frida-server
# 到 https://github.com/frida/frida/releases 找到与本机版本一致的 release
# 例如 frida --version 输出 16.2.1，则下载 frida-server-16.2.1-android-arm64.xz
```

### 1.3 确定设备架构

```bash
# 查看设备 CPU 架构
adb shell getprop ro.product.cpu.abi
# 常见输出:
#   arm64-v8a  → 下载 android-arm64 版本
#   armeabi-v7a → 下载 android-arm 版本
#   x86_64     → 下载 android-x86_64 版本（模拟器常见）
#   x86        → 下载 android-x86 版本
```

---

## 2. 设备配置

### 2.1 准备 Root 设备

动态分析需要 Root 权限的 Android 设备。推荐方案：

| 方案 | 适用场景 | 推荐度 |
|------|---------|--------|
| 已 Root 的真机 | 真实环境分析 | 最佳 |
| Magisk Root 的真机 | 需要通过 Root 检测 | 推荐 |
| Android 模拟器 (默认 Root) | 快速测试、学习 | 适合入门 |
| WSA (Windows) | Windows 环境 | 可用 |

**推荐模拟器**：
- Genymotion（x86，性能好，有免费版）
- Android Studio AVD（官方，ARM 支持越来越好）
- 夜神 / 雷电模拟器（国内常用，但部分加固检测较严）

### 2.2 部署 frida-server

```bash
# 1. 下载 frida-server（版本要和本机 frida-tools 一致！）
# 假设版本为 16.2.1，设备为 arm64
wget https://github.com/frida/frida/releases/download/16.2.1/frida-server-16.2.1-android-arm64.xz

# 2. 解压
xz -d frida-server-16.2.1-android-arm64.xz

# 3. 推送到设备
adb push frida-server-16.2.1-android-arm64 /data/local/tmp/frida-server

# 4. 设置权限
adb shell "chmod 755 /data/local/tmp/frida-server"

# 5. 启动 frida-server（需要 root）
adb shell "su -c '/data/local/tmp/frida-server -D &'"
# 注: -D 表示后台运行

# 6. 验证
frida-ps -U
# 应该能看到设备上运行的进程列表
```

### 2.3 验证连接

```bash
# 列出 USB 连接的设备
frida-ls-devices
# 应显示类似: id=emulator-5554 type=usb name=Android Emulator

# 列出设备进程
frida-ps -U
# 应显示进程列表，包含 PID 和进程名

# 如果使用网络连接（非 USB）
frida-ps -H <设备IP>:27042
```

### 2.4 常见连接问题

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `unable to connect to device` | frida-server 未运行 | `adb shell "su -c '/data/local/tmp/frida-server -D &'"` |
| `unable to find process` | 包名/进程名不正确 | `adb shell pm list packages \| grep keyword` 查找包名 |
| `server version mismatch` | frida 客户端和服务端版本不一致 | 确保版本完全一致 |
| `connection refused` | 端口被占用或 SELinux 阻止 | `adb shell "su -c 'setenforce 0'"` |
| ADB 设备离线 | USB 调试未授权 | 检查设备上的授权弹窗 |

---

## 3. 安装与配置

### 3.1 一键安装

```bash
# 克隆项目
git clone <repo-url> ai-reverse
cd ai-reverse

# 运行安装脚本
bash scripts/setup.sh
```

setup.sh 会自动完成以下步骤：
1. 检查 Python3、Java、ADB、uv、pip3、Git 是否安装
2. `pip install frida-mcp frida-tools`
3. 克隆 jadx-mcp-server 和 apktool-mcp-server 到 `deps/` 目录
4. 安装 MCP Server 的 Python 依赖
5. 从 `.mcp.json.template` 生成 `.mcp.json`（填入实际路径）
6. 验证工具可用性

### 3.2 手动安装（如 setup.sh 失败）

```bash
# 安装 Frida
pip3 install frida-mcp frida-tools

# 克隆 MCP Server
mkdir -p deps
git clone https://github.com/zinja-coder/jadx-mcp-server.git deps/jadx-mcp-server
git clone https://github.com/zinja-coder/apktool-mcp-server.git deps/apktool-mcp-server

# 安装依赖
pip3 install -r deps/jadx-mcp-server/requirements.txt
cd deps/apktool-mcp-server && uv sync && cd ../..

# 手动编辑 .mcp.json（从 .mcp.json.template 复制，替换路径占位符为实际绝对路径）
cp .mcp.json.template .mcp.json
# 编辑 .mcp.json，将 __JADX_MCP_PATH__ 替换为 deps/jadx-mcp-server 的绝对路径
# 将 __APKTOOL_MCP_PATH__ 替换为 deps/apktool-mcp-server 的绝对路径
```

### 3.3 验证安装

```bash
# 验证 Frida
frida --version

# 验证 frida-mcp
which frida-mcp

# 验证设备连接
frida-ps -U

# 在 Claude Code 中验证 MCP Server
# 打开 Claude Code，检查 jadx、apktool、frida 三个 MCP Server 是否可用
```

---

## 4. 在 Claude Code 中使用

### 4.1 启动

```bash
cd ai-reverse
claude   # 启动 Claude Code
```

Claude Code 会自动加载 `.mcp.json` 中配置的三个 MCP Server。

### 4.2 使用 Skill

在 Claude Code 中输入 `/android-re` 触发 Android 逆向 Skill，AI 会加载 SKILL.md 中定义的 6 大工作流。

### 4.3 自然语言指令示例

以下是常见的使用场景和对应的指令：

**场景 1：分析 APK 的 API 接口**
```
分析 target.apk 的所有 API 接口，输出完整的 API 文档
```

**场景 2：检测并脱壳**
```
检查 target.apk 是否有加固，如果有，帮我脱壳
```

**场景 3：还原加密算法**
```
分析 target.apk 中的登录请求加密算法，用 Python 复现
```

**场景 4：全流程分析**
```
对 target.apk 进行完整的逆向分析：脱壳、API 提取、算法还原
```

**场景 5：搜索特定代码**
```
在 target.apk 中搜索所有使用 AES 加密的代码
```

**场景 6：动态 Hook**
```
用 Frida hook com.target.app 的网络请求，抓取所有 API 调用
```

### 4.4 工作流程示例

以下是一个完整的逆向分析会话示例：

```
你: 帮我分析 com.example.app，提取它的 API 接口

AI: 我来为你进行分析。
    1. 首先用 jadx 打开 APK 进行静态分析...
       [调用 jadx MCP: open_file]
    2. 解析 Manifest 获取包信息...
       [调用 jadx MCP: get_manifest]
    3. 搜索 Retrofit 接口定义...
       [调用 jadx MCP: search_code "@GET"]
       [调用 jadx MCP: search_code "@POST"]
    4. 发现 3 个 API 接口类，读取源码...
       [调用 jadx MCP: get_source]
    5. 注入 trace-api.js 进行动态验证...
       [调用 frida MCP: spawn com.example.app]
       [调用 frida MCP: load_script trace-api.js]
    6. 整理输出 API 文档...
       [输出到 output/example-api.md]

你: 发现有些接口的参数是加密的，帮我还原加密算法

AI: 我来定位加密逻辑。
    1. 搜索加密相关代码...
       [调用 jadx MCP: search_code "Cipher"]
       [调用 jadx MCP: search_code "SecretKeySpec"]
    2. 找到加密类 com.example.crypto.AESUtil，读取源码...
       [调用 jadx MCP: get_source]
    3. 分析: 使用 AES/CBC/PKCS5Padding，密钥硬编码
    4. 注入 hook-crypto.js 验证...
       [调用 frida MCP: load_script hook-crypto.js]
    5. 用 Python 复现...
       [输出到 output/example-algorithm.md]
```

---

## 5. 独立使用 Frida 脚本

即使不使用 Claude Code，也可以独立使用 Frida 脚本。

### 5.1 基本命令

```bash
# spawn 模式（推荐）：以挂起模式启动应用，注入脚本后再恢复
frida -U -f <包名> -l <脚本路径>

# attach 模式：附加到已运行的进程
frida -U -n <进程名> -l <脚本路径>
# 或
frida -U <PID> -l <脚本路径>
```

### 5.2 各脚本独立使用

**DEX Dump（脱壳）**
```bash
frida -U -f com.target.app -l scripts/frida-scripts/dump-dex.js

# 脚本会自动等待应用加载完成，然后扫描并导出 DEX
# 导出的 DEX 数据通过 send() 发送，需要 Python 脚本接收：
python3 scripts/frida-scripts/dump-dex-recv.py com.target.app
```

**SSL Pinning 绕过**
```bash
frida -U -f com.target.app -l scripts/frida-scripts/ssl-unpin.js

# 绕过后即可用 Charles/mitmproxy 等代理工具抓包
# 脚本会输出各绕过模块的安装结果
```

**加密函数 Hook**
```bash
frida -U -f com.target.app -l scripts/frida-scripts/hook-crypto.js

# 然后在设备上操作应用触发加密操作
# 脚本会输出捕获的加密参数（算法、密钥、IV、明文、密文）
```

**HTTP API 追踪**
```bash
frida -U -f com.target.app -l scripts/frida-scripts/trace-api.js

# 操作应用的各个功能，脚本会输出所有 HTTP 请求详情
```

### 5.3 多脚本组合

```bash
# 绕过 SSL + 追踪 API（最常用的组合）
frida -U -f com.target.app \
  -l scripts/frida-scripts/ssl-unpin.js \
  -l scripts/frida-scripts/trace-api.js

# 绕过 SSL + Hook 加密（分析签名算法）
frida -U -f com.target.app \
  -l scripts/frida-scripts/ssl-unpin.js \
  -l scripts/frida-scripts/hook-crypto.js

# 全量 Hook（注意性能开销较大）
frida -U -f com.target.app \
  -l scripts/frida-scripts/ssl-unpin.js \
  -l scripts/frida-scripts/trace-api.js \
  -l scripts/frida-scripts/hook-crypto.js
```

---

## 6. 工作流详解

### 6.1 静态分析工作流

**适用场景**：初步了解应用结构、搜索关键代码。

```
步骤:
1. jadx open_file → 打开 APK
2. jadx get_manifest → 分析 Manifest
   - 提取包名、权限、四大组件
   - 检查 debuggable、networkSecurityConfig
3. jadx get_classes → 浏览类结构
   - 区分业务代码 vs 第三方库
4. jadx search_code → 关键字搜索
   - API: @GET, @POST, BaseUrl, Retrofit
   - 加密: Cipher, SecretKey, encrypt, decrypt
   - 网络: HttpURLConnection, WebView
5. jadx get_source → 读取目标类源码
6. jadx get_xrefs → 交叉引用追踪调用链
```

### 6.2 动态分析工作流

**适用场景**：需要运行时数据（网络请求、加密参数等）。

**前置条件检查清单**：
- [ ] Android 设备已连接（`adb devices`）
- [ ] frida-server 已在设备上运行（`frida-ps -U`）
- [ ] frida 客户端版本和服务端版本一致（`frida --version`）
- [ ] 目标应用已安装在设备上（`adb shell pm list packages | grep xxx`）

```
步骤:
1. frida spawn/attach → 连接目标应用
2. 选择并注入 Frida 脚本 → 安装 Hook
3. 在设备上操作应用 → 触发目标功能
4. 观察并收集 Frida 输出 → JSON 格式的数据
5. 关联静态分析的代码位置 → 完整理解
```

### 6.3 API 提取工作流

**适用场景**：需要获取应用的完整 API 列表和文档。

```
步骤:
1. [静态] jadx 搜索 Retrofit 注解和 OkHttp 配置
2. [静态] 提取 Base URL、接口路径、参数定义
3. [静态] 分析认证机制（Token/签名/API Key）
4. [动态] 注入 ssl-unpin.js 绕过证书校验
5. [动态] 注入 trace-api.js 抓取实际请求
6. [整合] 对比静态和动态发现，补全遗漏
7. [输出] 使用 templates/api-doc-template.md 格式输出
```

详细参考：`skills/android-re/references/api-extraction.md`

### 6.4 APK 脱壳工作流

**适用场景**：应用被加固（jadx 打开后看不到业务代码）。

```
步骤:
1. [检测] apktool decode → 检查 lib/ 下的特征 SO 文件
2. [检测] jadx 尝试打开 → 确认是否加固
3. [脱壳] frida spawn 目标应用
4. [脱壳] 注入 dump-dex.js → 等待内存扫描完成
5. [筛选] 按大小和包名筛选有效 DEX
6. [分析] jadx 打开 dump 出的 DEX → 继续静态分析
```

详细参考：`skills/android-re/references/unpacking.md`

### 6.5 算法还原工作流

**适用场景**：需要复现应用的加密/签名算法。

```
步骤:
1. [静态] jadx 搜索 Cipher/SecretKeySpec/MessageDigest
2. [静态] 分析算法类型、密钥来源、IV 生成方式
3. [静态] 追踪数据流：明文 → 加密 → 编码 → 传输
4. [动态] 注入 hook-crypto.js → 捕获运行时参数
5. [复现] 用 Python (pycryptodome) 编写等效代码
6. [验证] 对比 Python 输出与 Frida 捕获的密文
7. [输出] 使用 templates/algorithm-doc-template.md 输出
```

详细参考：`skills/android-re/references/algorithm-restore.md`

### 6.6 全流程工作流

**适用场景**：对全新目标应用进行完整逆向。

```
1. 初步检查
   ├── apktool decode → 是否加固？
   └── jadx 尝试打开 → 反编译质量？

2. 脱壳（如需要）
   ├── frida spawn
   ├── dump-dex.js
   └── jadx 打开 dump 的 DEX

3. 静态分析
   ├── Manifest 解析
   ├── 类结构浏览
   ├── API 定义搜索
   └── 加密逻辑搜索

4. 动态分析
   ├── ssl-unpin.js
   ├── trace-api.js → API 抓取
   └── hook-crypto.js → 加密参数

5. 文档输出
   ├── output/<app>-api.md
   └── output/<app>-algorithm.md
```

---

## 7. Frida 脚本参数详解

### 7.1 dump-dex.js 配置

```javascript
var config = {
    minDexSize: 0x70,              // DEX 最小合法大小（112 字节 = 完整头部）
    maxDexSize: 100 * 1024 * 1024, // DEX 最大合法大小（100 MB）
    autoStart: true,               // 是否在加载时自动开始扫描
    deepSearch: true,              // 是否启用深度搜索（对抗魔数抹零）
    waitSeconds: 5                 // 等待应用加载完成的秒数
};
```

**参数调优建议**：
- `waitSeconds`：加固应用通常需要更长的等待时间，建议设为 10-15 秒
- `deepSearch`：如果标准搜索已找到足够 DEX，可关闭以加速
- `minDexSize`：如果 dump 出很多小文件，可提高此值过滤

### 7.2 ssl-unpin.js 配置

```javascript
var config = {
    enableX509: true,              // X509TrustManager 绕过
    enableOkHttp: true,            // OkHttp3 CertificatePinner 绕过
    enableTrustManager: true,      // TrustManagerImpl.verifyChain 绕过
    enableNetworkSecurity: true,   // NetworkSecurityConfig 绕过
    enableWebView: true,           // WebViewClient SSL 错误绕过
    enableSSLContext: true,        // SSLContext.init 绕过
    enableHttpsURLConnection: true,// HttpsURLConnection 绕过
    verbose: false                 // 详细日志（每次 SSL 调用都会输出）
};
```

**注意事项**：
- 大多数情况下保持默认全开即可
- 如果目标应用使用 Flutter/React Native，Java 层绕过可能不够，需要 Native 层处理
- `verbose: true` 会输出大量日志，仅在调试绕过失败时开启

### 7.3 hook-crypto.js 配置

```javascript
var CONFIG = {
    hookCipher: true,          // Hook javax.crypto.Cipher
    hookDigest: true,          // Hook java.security.MessageDigest
    hookMac: true,             // Hook javax.crypto.Mac
    hookSignature: true,       // Hook java.security.Signature
    verbose: false,            // 详细模式
    maxDataLength: 256,        // 数据最大显示长度（字节）
    stackTraceDepth: 15        // 堆栈跟踪深度
};
```

**输出格式**：
```json
{
  "type": "crypto",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "operation": "Cipher.doFinal",
  "algorithm": "AES/CBC/PKCS5Padding",
  "mode": "ENCRYPT",
  "key": { "hex": "0123...", "base64": "ASNF..." },
  "iv": { "hex": "fedc..." },
  "input": { "hex": "48656c6c6f", "length": 5 },
  "output": { "hex": "a1b2c3...", "length": 16 },
  "stackTrace": "at com.example.crypto.AESUtil.encrypt..."
}
```

**调优建议**：
- `maxDataLength`：如果处理大文件加密，日志会被截断，可增大此值
- `stackTraceDepth`：增大可看到更完整的调用链，但日志更长
- 只需分析特定类型时，关闭不需要的 Hook（如只看 AES 则关闭 hookDigest/hookMac）

### 7.4 trace-api.js 配置

```javascript
var config = {
    hookOkHttp: true,            // Hook OkHttp3
    hookHttpURLConnection: true, // Hook HttpURLConnection
    hookWebView: true,           // Hook WebView
    urlWhitelist: [],            // URL 白名单（空 = 全部追踪）
    urlBlacklist: [],            // URL 黑名单
    maxBodyLength: 4096,         // Body 最大长度
    captureResponse: true,       // 是否捕获响应体
    verbose: false               // 详细日志
};
```

**URL 过滤示例**：
```javascript
// 只追踪目标 API 域名
urlWhitelist: ["api.target.com", "api2.target.com"],

// 排除静态资源和广告
urlBlacklist: [
    "googleapis.com",
    "crashlytics.com",
    ".png", ".jpg", ".css", ".js",
    "ad.doubleclick.net"
],
```

**输出格式**：
```json
{
  "type": "api",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "method": "POST",
  "url": "https://api.target.com/v1/login",
  "headers": { "Authorization": "Bearer xxx", "Content-Type": "application/json" },
  "requestBody": "{\"username\":\"test\",\"password\":\"encrypted...\"}",
  "statusCode": 200,
  "responseBody": "{\"code\":0,\"data\":{...}}",
  "duration": "156ms",
  "source": "OkHttp3"
}
```

---

## 8. 常见问题排查

### 8.1 setup.sh 相关

| 问题 | 解决方案 |
|------|---------|
| `pip3 install` 权限不足 | 使用 `pip3 install --user frida-mcp frida-tools` |
| `git clone` 失败 | 检查网络连接，尝试使用代理 |
| `uv sync` 失败 | 确认 uv 已正确安装: `uv --version` |
| 重新运行 setup.sh 不更新路径 | 已修复: setup.sh 每次从 `.mcp.json.template` 重新生成 |

### 8.2 MCP Server 相关

| 问题 | 解决方案 |
|------|---------|
| Claude Code 中看不到 MCP 工具 | 检查 `.mcp.json` 中的路径是否正确，重启 Claude Code |
| jadx MCP 启动报错 | 检查 Java 版本 `java -version`，需要 11+ |
| apktool MCP 启动报错 | 检查 uv 是否安装，运行 `cd deps/apktool-mcp-server && uv sync` |
| frida-mcp 启动报错 | 检查 `which frida-mcp`，可能需要重启终端 |

### 8.3 Frida 相关

| 问题 | 解决方案 |
|------|---------|
| `Failed to spawn: unable to find application` | 检查包名是否正确: `adb shell pm list packages \| grep xxx` |
| `Failed to attach: ambiguous name` | 使用 PID 而非进程名: `frida -U <PID> -l script.js` |
| `Process crashed` | 可能触发了反调试，尝试先注入反检测脚本 |
| `Script terminated` | 脚本语法错误，用 `node -c script.js` 检查语法 |
| Hook 后无输出 | 确认操作触发了目标代码路径 |
| dump-dex.js 无 DEX 输出 | 增大 `waitSeconds`，检查应用是否完全加载 |
| ssl-unpin.js 无法绕过 | 应用可能使用 Flutter/Native 层 SSL，需要其他方案 |

### 8.4 设备相关

| 问题 | 解决方案 |
|------|---------|
| `adb devices` 显示 unauthorized | 在设备上确认 USB 调试授权弹窗 |
| frida-server 无法启动 | 确认设备已 root，用 `su -c` 运行 |
| 应用检测到 root | 使用 Magisk Hide 隐藏 root |
| 应用检测到 Frida | 重命名 frida-server 或使用 frida-gadget 方式 |

---

## 9. 进阶技巧

### 9.1 自定义 Frida Hook

在 Frida 控制台中可以实时编写 Hook：

```javascript
// 在 frida REPL 中直接执行
Java.perform(function() {
    var TargetClass = Java.use("com.example.TargetClass");
    TargetClass.targetMethod.implementation = function(arg) {
        console.log("参数: " + arg);
        var result = this.targetMethod(arg);
        console.log("返回值: " + result);
        return result;
    };
});
```

### 9.2 修改脚本配置后重新加载

不需要重启应用，可以在 Frida 控制台中直接修改配置：

```javascript
// 在 frida REPL 中修改 trace-api.js 的配置
config.urlWhitelist = ["api.target.com"];
config.verbose = true;
```

### 9.3 导出 DEX 文件

dump-dex.js 通过 `send()` 发送二进制数据，需要 Python 接收脚本保存为文件。
也可以修改脚本直接写文件到设备：

```javascript
// 在 dump-dex.js 的 dumpDex 函数中添加写文件逻辑
var f = new File("/data/local/tmp/dump_" + dexIndex + ".dex", "wb");
f.write(dexBytes);
f.flush();
f.close();
```

然后从设备拉取：
```bash
adb pull /data/local/tmp/dump_0.dex ./output/
adb pull /data/local/tmp/dump_1.dex ./output/
```

### 9.4 处理反 Frida 检测

常见检测方式和绕过方案：

```bash
# 1. 重命名 frida-server
mv frida-server myserver
adb push myserver /data/local/tmp/
adb shell "su -c '/data/local/tmp/myserver -D &'"

# 2. 使用 Magisk + MagiskHide
# 在 Magisk 中对目标应用启用 MagiskHide

# 3. 修改 Frida 监听端口（避开默认的 27042）
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:8899 -D &'"
frida -H 127.0.0.1:8899 -f com.target.app -l script.js
```

### 9.5 使用输出模板

分析完成后，使用 `templates/` 中的模板格式化输出：

```bash
# 复制模板
cp templates/api-doc-template.md output/myapp-api.md
cp templates/algorithm-doc-template.md output/myapp-algorithm.md

# 在 Claude Code 中让 AI 填充模板
# 或手动编辑填入分析结果
```

---

## 附录

### A. MCP Server 工具速查

**jadx-mcp 常用工具**：`open_file`, `get_manifest`, `get_classes`, `search_code`, `get_source`, `get_xrefs`

**apktool-mcp 常用工具**：`decode`, `get_manifest`, `list_smali`, `get_smali`

**frida-mcp 常用工具**：`spawn`, `attach`, `run_script`, `load_script`, `list_devices`, `list_processes`

### B. 参考资源

- [Frida 官方文档](https://frida.re/docs/home/)
- [jadx 项目](https://github.com/skylot/jadx)
- [apktool 项目](https://ibotpeaches.github.io/Apktool/)
- [pycryptodome 文档](https://pycryptodome.readthedocs.io/)

### C. 安全声明

本工具仅用于合法的安全研究、逆向工程学习和授权的安全测试。使用者应确保遵守当地法律法规，不得用于未授权的应用分析或其他非法用途。
