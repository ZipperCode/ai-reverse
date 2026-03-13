---
name: android-re
description: Android 逆向工程框架，结合静态分析(jadx/apktool)与动态分析(Frida)，用于 API 提取、APK 脱壳、算法还原。当用户需要逆向 Android 应用时使用。
---

# Android 逆向工程 Skill

本 Skill 提供 6 大工作流（5 个专项 + 1 个全流程编排），覆盖 Android 应用逆向的完整链路。所有工作流基于 MCP 协议串联 jadx（静态）、apktool（资源）、frida（动态）三个 Server。

---

## 工作流 1: 静态分析

使用 jadx-mcp 对 APK 进行反编译和源码级分析。

### 步骤

1. **打开 APK**
   - 使用 jadx MCP `open_file` 工具加载目标 APK
   - 确认反编译成功，记录包名和入口 Activity

2. **解析 Manifest**
   - 使用 jadx `get_manifest` 获取 AndroidManifest.xml
   - 提取：包名、权限列表、四大组件（Activity/Service/Receiver/Provider）
   - 识别：`android:debuggable`、`networkSecurityConfig`、自定义 Application 类

3. **浏览类结构**
   - 使用 jadx `get_classes` 获取类列表
   - 按包名分组，识别业务代码 vs 第三方库
   - 常见第三方库包名：`com.google`、`okhttp3`、`retrofit2`、`com.squareup`、`androidx`

4. **关键字搜索**
   - 使用 jadx `search_code` 搜索目标关键字
   - 常用搜索词：
     - API 相关：`@GET`、`@POST`、`BaseUrl`、`Retrofit`、`OkHttpClient`
     - 加密相关：`Cipher`、`SecretKey`、`MessageDigest`、`encrypt`、`decrypt`、`sign`
     - 网络相关：`HttpURLConnection`、`WebView`、`loadUrl`
     - 认证相关：`token`、`Authorization`、`Bearer`、`api_key`

5. **阅读源码**
   - 使用 jadx `get_source` 获取目标类的反编译源码
   - 分析方法签名、参数、返回值
   - 识别混淆命名（单字母类名/方法名），尝试推断实际用途

6. **交叉引用**
   - 使用 jadx `get_xrefs` 追踪方法调用链
   - 从 API 接口定义向上追踪到调用点
   - 从加密方法向下追踪到数据流转

---

## 工作流 2: 动态分析

使用 frida-mcp 进行运行时 Hook 和数据采集。

### 前置条件
- Android 设备/模拟器已连接（`adb devices` 可见）
- Frida Server 已在设备上运行（`frida-ps -U` 可列出进程）

### 步骤

1. **启动目标应用**
   - 使用 frida-mcp `spawn` 以挂起模式启动目标应用（推荐）
   - 或使用 `attach` 附加到已运行的进程
   - spawn 模式可确保在应用初始化前就注入 Hook

2. **注入 Frida 脚本**
   - 根据分析目标选择脚本：
     - SSL 绕过：`scripts/frida-scripts/ssl-unpin.js`
     - API 追踪：`scripts/frida-scripts/trace-api.js`
     - 加密监控：`scripts/frida-scripts/hook-crypto.js`
     - DEX dump：`scripts/frida-scripts/dump-dex.js`
   - 使用 frida-mcp 的 `run_script` 或 `load_script` 注入

3. **操作应用并收集数据**
   - 在设备上操作目标功能（登录、下单、搜索等）
   - 观察 Frida 输出的 JSON 数据
   - 记录关键信息：URL、请求参数、加密算法、密钥

4. **分析采集结果**
   - 将 Frida 输出的 JSON 数据进行结构化分析
   - 关联静态分析中发现的代码位置
   - 验证或修正静态分析的推断

---

## 工作流 3: API 提取

结合静态搜索和动态抓包，提取应用的完整 API 列表。

详细参考：`references/api-extraction.md`

### 步骤

1. **静态提取**
   - jadx 搜索 Retrofit 接口注解：`@GET`、`@POST`、`@PUT`、`@DELETE`
   - 搜索 Base URL 定义：`BASE_URL`、`baseUrl`、`Retrofit.Builder`
   - 搜索请求头：`@Headers`、`@Header`、`addHeader`、`Interceptor`
   - 搜索认证逻辑：`Authorization`、`Bearer`、`Token`

2. **动态抓取**
   - 注入 `ssl-unpin.js`（如需绕过 SSL Pinning）
   - 注入 `trace-api.js` 捕获实际 HTTP 请求
   - 操作应用的各个功能模块
   - 收集完整的请求/响应数据

3. **关联分析**
   - 将静态发现的 API 定义与动态抓取的实际请求对比
   - 补充静态未覆盖的 API（如动态拼接的 URL）
   - 确认参数格式、认证方式、响应结构

4. **文档输出**
   - 使用 `templates/api-doc-template.md` 格式
   - 输出到 `output/<app-name>-api.md`
   - 包含：Base URL、认证方式、每个端点的详细信息

---

## 工作流 4: APK 脱壳（DEX Dump）

对加固应用进行脱壳，获取原始 DEX 文件。

详细参考：`references/unpacking.md`

### 步骤

1. **检测加固方案**
   - 使用 apktool `decode` 解包 APK
   - 检查 `lib/` 目录下的 SO 文件特征：
     - 360 加固：`libjiagu.so`、`libjiagu_art.so`
     - 腾讯乐固：`libshella*.so`、`libBugly.so`
     - 梆梆加固：`libSecShell.so`、`libDexHelper.so`
     - 爱加密：`libexec.so`、`libexecmain.so`
     - 百度加固：`libbaiduprotect.so`
   - 使用 jadx 尝试打开，如果主要类无法反编译，确认已加固

2. **Frida spawn 启动**
   - 使用 frida-mcp 以 spawn 模式启动目标应用
   - 确保在壳代码解密完成后再 dump

3. **注入 dump 脚本**
   - 注入 `scripts/frida-scripts/dump-dex.js`
   - 脚本会自动：
     - 等待应用加载完成（可配置等待时间）
     - 扫描进程内存中的 DEX
     - 检测并报告加固方案
     - 导出所有有效 DEX 文件

4. **筛选 DEX**
   - 按大小筛选：过小的 DEX（<10KB）通常是框架壳
   - 按包名筛选：包含应用包名的 DEX 是目标
   - 排除系统框架 DEX

5. **jadx 分析**
   - 使用 jadx-mcp 打开 dump 出的 DEX 文件
   - 验证反编译质量
   - 继续进行静态分析工作流

---

## 工作流 5: 算法还原

定位应用中的加密/签名算法，捕获运行时参数，并用 Python 复现。

详细参考：`references/algorithm-restore.md`

### 步骤

1. **静态定位**
   - jadx 搜索加密关键字：`Cipher`、`SecretKeySpec`、`MessageDigest`、`Mac`
   - 追踪调用链，定位加密入口方法
   - 分析算法类型、密钥来源、IV 生成方式
   - 识别混淆后的加密包装类

2. **映射数据流**
   - 追踪从原始数据到加密结果的完整流程
   - 确认加密链：明文 → 序列化 → 加密 → 编码 → 传输
   - 识别多层加密（如先 AES 再 Base64 再 URL 编码）

3. **动态捕获**
   - 注入 `scripts/frida-scripts/hook-crypto.js`
   - 操作触发目标加密流程的功能
   - 捕获：算法名、密钥(hex/base64)、IV、明文、密文
   - 记录调用栈以关联到源码位置

4. **Python 复现**
   - 根据捕获的参数编写 Python 代码
   - 常见模式：
     - AES-CBC: `from Crypto.Cipher import AES`
     - AES-GCM: `AES.new(key, AES.MODE_GCM, nonce=iv)`
     - RSA: `from Crypto.PublicKey import RSA`
     - HMAC: `import hmac, hashlib`
   - 使用捕获的明文和密钥验证输出是否与捕获的密文一致

5. **验证与文档**
   - 对比 Python 输出与 Frida 捕获的密文
   - 使用 `templates/algorithm-doc-template.md` 格式输出
   - 输出到 `output/<app-name>-algorithm.md`

---

## 工作流 6: 全流程编排

针对一个全新的目标应用，按以下顺序执行完整逆向分析：

```
1. 初步检查
   ├── apktool decode → 检查是否加固
   └── jadx 尝试打开 → 评估反编译质量

2. 脱壳（如需要）
   ├── frida spawn 目标应用
   ├── 注入 dump-dex.js
   └── jadx 打开 dump 出的 DEX

3. 静态分析
   ├── 解析 Manifest
   ├── 浏览类结构
   ├── 搜索 API 定义
   └── 搜索加密逻辑

4. 动态分析
   ├── 注入 ssl-unpin.js（如需）
   ├── 注入 trace-api.js → 收集 API
   └── 注入 hook-crypto.js → 收集加密参数

5. 输出文档
   ├── API 文档 → output/<app>-api.md
   └── 算法文档 → output/<app>-algorithm.md
```

---

## 工具速查

### jadx-mcp 常用工具
- `open_file` - 打开 APK/DEX
- `get_manifest` - 获取 Manifest
- `get_classes` - 获取类列表
- `search_code` - 代码搜索
- `get_source` - 获取源码
- `get_xrefs` - 交叉引用

### apktool-mcp 常用工具
- `decode` - 解包 APK
- `get_manifest` - 获取 Manifest
- `list_smali` - 列出 Smali 文件
- `get_smali` - 获取 Smali 源码

### frida-mcp 常用工具
- `spawn` - 以挂起模式启动应用
- `attach` - 附加到运行中的进程
- `run_script` / `load_script` - 注入 JS 脚本
- `list_devices` - 列出连接设备
- `list_processes` - 列出进程

### Frida 脚本
- `dump-dex.js` - DEX 内存 dump，配置项：`minDexSize`、`waitSeconds`、`deepSearch`
- `ssl-unpin.js` - SSL Pinning 绕过，支持独立开关各 bypass
- `hook-crypto.js` - 加密函数 Hook，输出 JSON 含 key/IV/数据/调用栈
- `trace-api.js` - HTTP 请求追踪，支持 URL 白/黑名单过滤
