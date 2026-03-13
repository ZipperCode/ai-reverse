# Android APK 脱壳参考指南

本文档为 APK 脱壳（Unpacking / Unshelling）的详细参考，涵盖加固方案识别、脱壳策略选择、工具使用及常见问题排查。

---

## 1. 加固方案检测矩阵

| 加固方案 | 厂商 | 特征 SO 文件 | 特征文件/目录 | 检测方法 |
|---------|------|-------------|-------------|---------|
| 360加固 | 奇虎360 | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so` | `assets/libjiagu.so` | SO 文件名匹配；classes.dex 极小且仅含壳入口类 |
| 腾讯乐固 | 腾讯 | `libshella-2.so`, `libshellx-2.so`, `libtup.so` | `assets/0OO00l111l1l`, `tencent_stub` | SO 文件名匹配；assets 下含混淆命名文件 |
| 梆梆加固 | 梆梆安全 | `libSecShell.so`, `libDexHelper.so`, `libsecexe.so` | `assets/secData0.jar` | SO 文件名匹配；assets 下含 secData 系列文件 |
| 爱加密 | 爱加密 | `libexec.so`, `libexecmain.so` | `ijiami.dat`, `assets/ijiami.dat` | SO 文件名匹配；根目录或 assets 含 `ijiami.dat` |
| 百度加固 | 百度 | `libbaiduprotect.so`, `libbaiduprotect_x86.so` | `assets/baiduprotect.jar` | SO 文件名匹配；assets 含 baiduprotect 相关文件 |
| 网易易盾 | 网易 | `libnesec.so`, `libnetease.so` | `assets/neprotect` 目录 | SO 文件名匹配；assets 含 neprotect 目录 |
| 数字联盟 | 数字联盟 | `libdl-protection.so`, `libegis.so` | `assets/dp.data` | SO 文件名匹配；assets 下含 dp.data |
| 通付盾 | 通付盾 | `libchaosvmp.so`, `libchaosprotect.so` | `assets/tosprotection` 目录 | SO 文件名匹配；含 chaos 系列 SO |
| 海云安 | 海云安 | `libitsec.so`, `libapssec.so` | `assets/itsec.dat` | SO 文件名匹配；assets 含 itsec 相关文件 |
| 几维安全 | 几维安全 | `libkwscmm.so`, `libkwslinker.so` | `assets/dex.dat` | SO 文件名匹配；含 kws 前缀 SO 文件 |
| 顶象 | 顶象科技 | `libx3g.so`, `libdxbase.so` | `assets/dx_res` 目录 | SO 文件名匹配；assets 含 dx_res 目录结构 |
| APKProtect | APKProtect | `libAPKProtect.so` | `assets/apkprotect.data` | SO 文件名匹配；含 APKProtect 标识 |

### 快速检测流程

```
1. apktool decode target.apk -o output/
2. 检查 output/lib/ 下各架构目录中的 SO 文件名
3. 检查 output/assets/ 下的特征文件和目录
4. 用 jadx 尝试打开 APK，若主业务类无法反编译或仅见壳入口类，确认已加固
5. 运行时检测：frida 注入后通过 Process.enumerateModules() 匹配特征 SO
```

---

## 2. 脱壳策略

### 2.1 一代壳 -- DEX 整体加密

**原理：** 将原始 classes.dex 整体加密存储于 APK 内（通常放在 assets 或 SO 中），运行时由壳代码解密到内存后通过 `DexClassLoader` / `InMemoryDexClassLoader` 加载。

**识别特征：**
- classes.dex 极小（几 KB ~ 几十 KB），仅包含壳的 Application 类
- jadx 打开后只能看到壳入口类（如 `StubApplication`、`ProxyApplication`）
- assets 中存在加密的 DEX/JAR 文件

**脱壳策略：**
- 直接内存 dump 即可获取完整 DEX
- 等待壳代码解密完成后，扫描进程内存中的 DEX 魔数
- 使用 `dump-dex.js` 默认模式即可，`waitSeconds` 设为 5~10 秒

**推荐等待时间：** 5~10 秒

### 2.2 二代壳 -- DEX 函数抽取（指令抽取 / CodeItem 加密）

**原理：** DEX 文件结构保留，但每个方法的 `code_item`（字节码指令）被抽取或加密。壳在方法首次执行时才解密还原指令（即"按需解密"）。

**识别特征：**
- jadx 能看到类结构和方法签名，但方法体为空或仅含 `nop` / `return-void`
- dump 出的 DEX 用 jadx 打开后，大量方法体为空
- DEX 文件大小正常，但 `code_item` 区域数据异常

**脱壳策略：**
- 简单内存 dump 只能拿到"空壳" DEX
- 需要在每个函数被调用执行时 dump，或主动触发所有函数的解密
- 常用方案：
  1. **FART（ART 环境下脱壳）**：修改 ART 运行时，在类加载时主动调用所有方法的解密逻辑
  2. **Frida 主动调用**：Hook `ClassLoader.loadClass()`，对每个类的所有方法触发一次调用
  3. **延迟 dump**：反复操作应用各功能后再 dump，尽可能让更多方法被解密
- `dump-dex.js` 配合 `deepSearch: true` 并增加 `waitSeconds` 至 15~30 秒

**推荐等待时间：** 15~30 秒，且需要在 dump 前尽量多地操作应用界面

### 2.3 三代壳 -- VMP / DEX2C（代码虚拟化 / 原生化）

**原理：**
- **VMP（虚拟机保护）**：将 Java 字节码转换为自定义虚拟机指令，运行时由自定义解释器执行
- **DEX2C**：将 Java 方法直接编译为 Native C/C++ 代码，编译进 SO 文件

**识别特征：**
- jadx 中关键方法体为 native 声明，但对应 SO 中找不到标准 JNI 导出符号
- 方法体中只有一条 `native` 调用，实际逻辑在 SO 中
- SO 文件体积异常大（包含大量转换后的代码）
- 存在自定义指令集解释器的特征函数

**脱壳策略：**
- 传统 DEX dump 无法恢复被虚拟化/原生化的方法
- 可能的处理方案：
  1. **部分恢复**：dump DEX 可获取未被保护的方法，核心方法需单独分析
  2. **SO 逆向**：使用 IDA Pro / Ghidra 分析 SO 中的转换后代码
  3. **动态 Hook**：不尝试还原代码，直接 Hook JNI 调用层捕获输入输出
  4. **VMP 指令跟踪**：trace 自定义解释器的 dispatch 循环，记录操作码和操作数

**注意：** 三代壳保护的代码通常无法完全恢复为原始 Java 源码，实际分析中应优先使用动态 Hook 捕获关键数据。

### 2.4 各代壳识别速查

| 特征 | 一代壳 | 二代壳 | 三代壳 |
|------|-------|-------|-------|
| classes.dex 大小 | 极小（仅壳入口） | 正常大小 | 正常大小 |
| jadx 类列表 | 仅壳类可见 | 完整类结构可见 | 完整类结构可见 |
| jadx 方法体 | 完全不可见 | 方法体为空/nop | 为 native 声明 |
| dump DEX 效果 | 可完整恢复 | 需特殊处理才完整 | 核心方法不可恢复 |
| 推荐脱壳工具 | dump-dex.js | FART / Frida 主动调用 | IDA + Frida Hook |

---

## 3. dump-dex.js 配置与使用

### 3.1 配置参数说明

`dump-dex.js` 脚本头部定义了以下可配置参数：

```javascript
var config = {
    minDexSize: 0x70,              // DEX 最小合法大小（112 字节，即 DEX 头部大小）
    maxDexSize: 100 * 1024 * 1024, // DEX 最大合法大小（100 MB，防止误判）
    autoStart: true,               // 脚本加载后是否自动开始扫描
    deepSearch: true,              // 是否启用深度搜索（搜索魔数被破坏的 DEX）
    waitSeconds: 5                 // 等待应用初始化的秒数（壳解密需要时间）
};
```

| 参数 | 默认值 | 说明 | 调优建议 |
|------|--------|------|---------|
| `minDexSize` | `0x70` (112B) | 过滤过小的假阳性 | 一般无需修改；若结果太多可提高到 `0x1000` 过滤微小 DEX |
| `maxDexSize` | `100MB` | 过滤过大的假阳性 | 一般无需修改 |
| `autoStart` | `true` | 自动启动扫描 | 设为 `false` 可手动调用 `rpc.exports.start()` 控制时机 |
| `deepSearch` | `true` | 深度搜索模式 | 一代壳可关闭以加快速度；遇到魔数被抹零的壳必须开启 |
| `waitSeconds` | `5` | 等待秒数 | 一代壳 5~10 秒；二代壳 15~30 秒；启动慢的应用可设更高 |

### 3.2 spawn 模式 vs attach 模式

**spawn 模式（推荐）：**

```bash
frida -U -f com.target.app -l dump-dex.js --no-pause
```

- Frida 主动启动目标应用，从 `zygote fork` 起就注入
- 可确保在壳代码执行前就完成 Hook 准备
- 适用于所有壳类型，尤其是需要在初始化阶段捕获的场景
- `--no-pause` 参数让应用启动后不暂停，自动继续执行

**attach 模式：**

```bash
# 先手动启动应用，等待其完全加载
frida -U com.target.app -l dump-dex.js
```

- 附加到已运行的进程
- 适用于：壳已经完成解密、需要在特定操作后 dump 的场景
- 优点：应用已完全初始化，不受 `waitSeconds` 限制
- 缺点：如果壳有反调试检测，可能在 attach 前就已触发

**选择建议：**

| 场景 | 推荐模式 | 说明 |
|------|---------|------|
| 首次尝试脱壳 | spawn | 确保从头注入 |
| spawn 失败或崩溃 | attach | 避免注入时机冲突 |
| 需要操作应用后再 dump | attach | 等操作完成后附加 |
| 存在反调试检测 | spawn + 反检测脚本 | 需提前绕过检测 |

### 3.3 等待时间调优

`waitSeconds` 控制脚本注入后等待多久再开始扫描内存。等待是为了让壳代码有足够时间完成 DEX 解密。

**调优原则：**
- 等待过短：壳尚未解密完成，dump 出的 DEX 不完整或为空
- 等待过长：无副作用，但浪费时间
- 建议从默认值开始，若 dump 结果不理想则逐步增加

**参考值：**

| 壳类型 | 建议等待时间 | 说明 |
|--------|------------|------|
| 360加固 | 5~8 秒 | 解密较快 |
| 腾讯乐固 | 5~10 秒 | 中等速度 |
| 梆梆加固 | 8~15 秒 | 可能有多轮解密 |
| 爱加密 | 5~10 秒 | 解密较快 |
| 百度加固 | 5~10 秒 | 中等速度 |
| 未知壳 | 15~30 秒 | 保守策略，确保充足时间 |

### 3.4 深度搜索模式

部分加固方案会在 DEX 加载到内存后抹除文件头部的魔数（`dex\n035`），以对抗基于魔数匹配的 dump 工具。

**深度搜索原理：**

标准扫描搜索 DEX 魔数 `64 65 78 0a 30 33`，但深度搜索转而搜索 DEX 头部中不易被篡改的结构特征：
- `header_size = 0x70`（偏移 0x24，固定值）
- `endian_tag = 0x12345678`（偏移 0x28，固定值）
- 连续搜索模式：`70 00 00 00 78 56 34 12`

匹配到后回退 0x24 字节得到 DEX 起始地址，再校验 `file_size`、`string_ids_size`、`type_ids_size` 等字段确认合法性。

**何时开启：**
- 标准扫描未找到预期数量的 DEX 时
- 已知目标壳会抹除魔数时（部分 360加固版本、部分梆梆加固版本）
- 默认已开启，建议保持

---

## 4. dump 后 DEX 筛选

dump 完成后通常会得到多个 DEX 文件，需要筛选出包含目标业务代码的 DEX。

### 4.1 按文件大小过滤

```
规则：
- < 10 KB    → 几乎肯定是壳框架 DEX 或空壳，直接排除
- 10~100 KB  → 可能是壳相关或小型工具 DEX，需进一步确认
- 100 KB~1 MB → 可能是第三方 SDK 的 DEX
- > 1 MB     → 大概率包含业务代码，优先分析
```

**实际操作：**
```bash
# 列出所有 dump 出的 DEX 及其大小，按大小降序排列
ls -lhS dumped_dex_*.dex

# 删除过小的 DEX
find . -name "dumped_dex_*.dex" -size -10k -delete
```

### 4.2 按包名过滤

使用 jadx 或 `dexdump` 工具检查每个 DEX 中是否包含目标应用的包名：

```bash
# 使用 strings 快速搜索包名
strings dumped_dex_0.dex | grep "com.target.app"

# 使用 dexdump 查看类列表
dexdump -f dumped_dex_0.dex | grep "com.target.app"

# 批量检查所有 DEX
for f in dumped_dex_*.dex; do
    echo "=== $f ==="
    strings "$f" | grep -c "com.target.app"
done
```

包含目标包名的 DEX 即为业务代码所在的 DEX，优先分析。

### 4.3 排除系统框架 DEX

dump 过程中可能会捕获到系统框架（Android Framework）的 DEX，需要排除：

**常见系统框架 DEX 特征：**
- 包含 `android.` / `com.android.` / `dalvik.` / `java.` 前缀的类
- 不包含任何目标应用包名的类
- 与设备系统版本对应的框架 DEX（通常很大，几十 MB）

**排除方法：**
```bash
# 检查 DEX 中是否包含系统框架特征包名
strings dumped_dex_0.dex | grep -E "^Landroid/(app|widget|os|content)" | head -5

# 如果大量匹配系统类且不含目标包名，则为系统框架 DEX，排除
```

### 4.4 多 DEX 合并策略

当目标应用使用 MultiDex（classes.dex, classes2.dex, ...）时，dump 出的多个 DEX 可能分别对应各个 DEX 文件。

**合并方法：**

1. **直接用 jadx 打开多个 DEX**：
   ```bash
   jadx -d output/ dumped_dex_1.dex dumped_dex_2.dex dumped_dex_3.dex
   ```

2. **重新打包为 APK/ZIP**：
   ```bash
   # 重命名为标准多 DEX 命名
   cp dumped_dex_1.dex classes.dex
   cp dumped_dex_2.dex classes2.dex
   cp dumped_dex_3.dex classes3.dex

   # 打包为 ZIP（可被 jadx 直接打开）
   zip merged.zip classes.dex classes2.dex classes3.dex
   ```

3. **使用 jadx-mcp 逐个分析**：通过 `open_file` 依次打开每个 DEX，分别搜索目标代码。

**注意：** 合并前确保排除了壳 DEX 和系统框架 DEX，否则会干扰分析。

---

## 5. 反 Frida 检测绕过

许多加固方案会检测 Frida 的存在并终止应用，需要提前绕过。

### 5.1 常见检测方式

#### 端口检测（27042）

Frida Server 默认监听 TCP 27042 端口，壳代码通过尝试连接该端口来判断 Frida 是否运行。

```java
// 典型检测代码
try {
    Socket socket = new Socket("127.0.0.1", 27042);
    socket.close();
    // Frida 存在，退出应用
    System.exit(0);
} catch (Exception e) {
    // 端口未开放，安全
}
```

#### 进程名检测

扫描 `/proc/self/maps` 或 `ps` 输出，搜索 `frida-server`、`frida-agent` 等关键字。

```java
// 检查运行中的进程名
Process process = Runtime.getRuntime().exec("ps");
// 搜索包含 "frida" 的进程
```

#### maps 文件检测

读取 `/proc/self/maps`，检查是否有 `frida-agent`、`frida-gadget` 相关的内存映射：

```java
BufferedReader reader = new BufferedReader(
    new FileReader("/proc/self/maps"));
String line;
while ((line = reader.readLine()) != null) {
    if (line.contains("frida") || line.contains("gadget")) {
        // 检测到 Frida
    }
}
```

#### D-Bus 协议检测

Frida 使用 D-Bus 协议通信，壳代码向 Frida 端口发送 D-Bus AUTH 消息，通过响应判断 Frida 存在：

```c
// 向端口发送 D-Bus 空认证消息
send(sock, "\x00", 1, 0);
send(sock, "AUTH\r\n", 6, 0);
// 检查是否收到 REJECTED 响应（Frida 特征响应）
```

### 5.2 绕过方案

#### 方案 A：重命名 frida-server

修改 frida-server 的二进制名称以规避进程名检测：

```bash
# 重命名 frida-server
mv frida-server frida-server-renamed
# 或使用随机名称
cp frida-server /data/local/tmp/fs_12345
chmod 755 /data/local/tmp/fs_12345

# 以非默认端口启动
/data/local/tmp/fs_12345 -l 0.0.0.0:8888 &

# 连接时指定端口
frida -H 127.0.0.1:8888 -f com.target.app -l dump-dex.js --no-pause
```

#### 方案 B：使用 Magisk Hide / Shamiko / Zygisk

```bash
# Magisk Hide（Magisk v23 及以下）
# 在 Magisk Manager 中将目标应用加入 Hide 列表

# Shamiko（Magisk v24+）
# 安装 Shamiko 模块，配合 Zygisk 使用
# 在 DenyList 中添加目标应用
```

#### 方案 C：Hook 检测函数（Frida 脚本绕过）

```javascript
// 通杀型反检测绕过脚本示例
Java.perform(function() {
    // 1. Hook Runtime.exec() 防止 ps 命令检测
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("ps") !== -1 || cmd.indexOf("frida") !== -1) {
            console.log("[反检测] 拦截命令: " + cmd);
            return this.exec("echo blocked");
        }
        return this.exec(cmd);
    };

    // 2. Hook File 操作防止 maps 文件检测
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("frida") !== -1 || path.indexOf("magisk") !== -1) {
            console.log("[反检测] 隐藏文件: " + path);
            return false;
        }
        return this.exists();
    };
});

// 3. Native 层 Hook：拦截 open() 对 /proc/self/maps 的读取
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && path.indexOf("/proc/self/maps") !== -1) {
            this.shouldFilter = true;
        }
    },
    onLeave: function(retval) {
        if (this.shouldFilter) {
            // 可以选择返回 -1 或替换为其他文件描述符
        }
    }
});

// 4. 拦截 socket 连接（防止端口检测）
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
    onEnter: function(args) {
        var sockAddr = args[1];
        var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
        if (port === 27042) {
            console.log("[反检测] 拦截对 27042 端口的连接");
            // 修改端口使连接失败
            sockAddr.add(2).writeU8(0);
            sockAddr.add(3).writeU8(0);
        }
    }
});
```

#### 方案 D：使用 Frida Gadget（免 Server 模式）

将 `frida-gadget.so` 注入 APK 中，无需运行 frida-server，可规避大部分基于进程名和端口的检测：

```bash
# 1. 解包 APK
apktool d target.apk -o target_unpacked/

# 2. 将 frida-gadget.so 放入 lib 对应架构目录
cp frida-gadget-android-arm64.so target_unpacked/lib/arm64-v8a/libfrida-gadget.so

# 3. 在 smali 入口处添加 System.loadLibrary("frida-gadget")
# 4. 重打包并签名
apktool b target_unpacked/ -o target_patched.apk
```

---

## 6. 常见问题排查

### 6.1 dump 出空 DEX

**现象：** dump 出的 DEX 文件大小为 0 或极小（仅包含头部），jadx 打开后无内容。

**可能原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 等待时间不足，壳尚未完成解密 | 增加 `waitSeconds`（建议 15~30 秒） |
| 使用 attach 模式但壳已清除内存中的 DEX | 改用 spawn 模式，在初始化阶段 dump |
| 壳使用了内存保护（mprotect） | 检查内存权限，尝试 Hook `mprotect` 阻止权限回收 |
| 壳在 dump 时机之前就已解密并重新加密 | 尝试 Hook `DexFile` 或 `ClassLoader` 相关方法，在加载瞬间 dump |

### 6.2 dump 不完整

**现象：** DEX 能用 jadx 打开，能看到类结构，但大量方法体为空。

**可能原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 二代壳（函数抽取壳），方法体按需解密 | 使用 FART 框架或 Frida 主动调用触发解密 |
| dump 时部分方法尚未被执行 | 在 dump 前充分操作应用，触发更多方法加载 |
| DEX 文件跨越内存区域边界，读取被截断 | 查看 dump 日志中的跨区域警告，尝试手动指定 dump 范围 |

**二代壳补充 dump 方法：**
```javascript
// Frida 脚本：主动触发类加载以促进二代壳解密
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                // 尝试通过 ClassLoader 加载目标类触发解密
                loader.loadClass("com.target.app.MainActivity");
            } catch(e) {}
        },
        onComplete: function() {}
    });
});
```

### 6.3 应用崩溃

**现象：** 注入 Frida 脚本后应用闪退或直接崩溃。

**可能原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 反 Frida 检测导致应用自杀 | 先注入反检测脚本，再注入 dump 脚本（参考第 5 节） |
| 注入时机过早，壳初始化未完成 | 使用 attach 模式替代 spawn，或增加脚本中的延迟 |
| Frida 版本与设备不兼容 | 确保 frida-server 版本与 Python frida 包版本完全一致 |
| SELinux 限制 | `adb shell setenforce 0` 临时关闭 SELinux |
| 脚本 Hook 了关键系统函数导致死锁 | 精简 Hook 范围，避免在壳初始化阶段 Hook 过多函数 |

### 6.4 Frida 无法 attach

**现象：** `frida -U com.target.app` 报错 `Failed to attach` 或找不到进程。

**排查步骤：**

```bash
# 1. 确认设备连接正常
adb devices

# 2. 确认 frida-server 正在运行
adb shell "ps | grep frida"
# 如未运行，启动：
adb shell "/data/local/tmp/frida-server &"

# 3. 确认 frida-server 架构正确（arm / arm64 / x86）
adb shell getprop ro.product.cpu.abi
# 对比下载的 frida-server 架构是否匹配

# 4. 确认版本一致
frida --version                         # 宿主端版本
adb shell "/data/local/tmp/frida-server --version"  # 设备端版本
# 两者必须完全一致

# 5. 确认目标进程存在
frida-ps -U | grep target

# 6. 如果使用模拟器，确认 USB 模式可用
frida-ps -U
# 若不行尝试 TCP 模式
frida-ps -H 127.0.0.1:27042

# 7. 权限问题
adb root
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

**常见错误与解决：**

| 错误信息 | 原因 | 解决 |
|---------|------|------|
| `unable to find process with name` | 进程名不匹配 | 用 `frida-ps -U` 查看精确进程名 |
| `unable to connect to remote frida-server` | frida-server 未运行 | 启动 frida-server |
| `incompatible Frida version` | 版本不一致 | 统一宿主端和设备端版本 |
| `need Gadget to attach on jailed iOS` | 设备无 root | root 设备或使用 Frida Gadget 方案 |
| `process crashed: Aborted` | 反调试检测 | 先注入反检测绕过脚本 |

---

## 附录：脱壳操作检查清单

```
[ ] 1. 确认环境就绪
    [ ] adb devices 可见目标设备
    [ ] frida-server 已启动且版本匹配
    [ ] 目标 APK 已安装到设备

[ ] 2. 检测加固方案
    [ ] apktool 解包检查 SO 和 assets 特征
    [ ] jadx 初步查看确认加固

[ ] 3. 选择脱壳策略
    [ ] 确定壳代数（一代/二代/三代）
    [ ] 配置 dump-dex.js 参数（waitSeconds / deepSearch）
    [ ] 准备反 Frida 检测绕过脚本（如需要）

[ ] 4. 执行脱壳
    [ ] frida spawn 模式注入 dump-dex.js
    [ ] 观察日志确认 DEX 被成功 dump
    [ ] 如有反检测，先注入绕过脚本

[ ] 5. 筛选与验证
    [ ] 按大小排除过小的 DEX
    [ ] 按包名确认目标 DEX
    [ ] 排除系统框架 DEX
    [ ] jadx 打开验证反编译质量

[ ] 6. 后续分析
    [ ] 使用 jadx-mcp 对 dump 出的 DEX 进行静态分析
    [ ] 继续 API 提取或算法还原工作流
```
