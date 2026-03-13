/**
 * Frida DEX 内存转储脚本
 * 用途：从加壳的 Android 应用进程内存中搜索并导出 DEX 文件
 *
 * 工作原理：
 *   1. 枚举进程所有可读内存区域
 *   2. 扫描 DEX 魔数 (dex\n035 ~ dex\n039)
 *   3. 解析 DEX 头部，校验合法性后导出
 *   4. 支持深度搜索（针对魔数被抹零的情况，通过 map_list 特征定位）
 *   5. 自动识别主流加固方案
 *
 * 使用方式：
 *   frida -U -f com.target.app -l dump-dex.js --no-pause
 *   或
 *   frida -U com.target.app -l dump-dex.js
 */

"use strict";

// ============================================================================
// 配置项 —— 根据实际场景调整
// ============================================================================
var config = {
    minDexSize: 0x70,           // DEX 最小合法大小（至少包含完整头部，112 字节）
    maxDexSize: 100 * 1024 * 1024, // DEX 最大合法大小（100 MB）
    autoStart: true,            // 是否自动开始扫描
    deepSearch: true,           // 是否启用深度搜索（搜索被抹除魔数的 DEX）
    waitSeconds: 5              // 等待应用完全加载的秒数
};

// ============================================================================
// 全局状态
// ============================================================================
var dexFound = [];              // 已发现的 DEX 信息列表
var dexIndex = 0;               // DEX 编号计数器
var scannedRanges = 0;          // 已扫描的内存区域数量

// DEX 魔数列表：dex\n035 到 dex\n039
var DEX_MAGICS = [
    [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],  // dex\n035
    [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x36, 0x00],  // dex\n036
    [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00],  // dex\n037
    [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00],  // dex\n038
    [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00]   // dex\n039
];

// ============================================================================
// 已知加固方案特征库
// ============================================================================
var PACKER_SIGNATURES = {
    "360加固 (360jiagu)": ["libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so"],
    "腾讯乐固 (Tencent Legu)": ["libshella-2.so", "libshellx-2.so", "libBugly.so", "libtup.so"],
    "梆梆加固 (Bangbang)": ["libSecShell.so", "libDexHelper.so", "libsecexe.so"],
    "爱加密 (ijiami)": ["libexec.so", "libexecmain.so", "ijiami.dat"],
    "百度加固 (Baidu)": ["libbaiduprotect.so", "libbaiduprotect_x86.so"]
};

// ============================================================================
// 工具函数
// ============================================================================

/**
 * 格式化日志输出，附带时间戳
 * @param {string} tag - 日志标签
 * @param {string} msg - 日志内容
 */
function log(tag, msg) {
    var now = new Date();
    var ts = now.getHours() + ":" +
             ("0" + now.getMinutes()).slice(-2) + ":" +
             ("0" + now.getSeconds()).slice(-2);
    console.log("[" + ts + "][" + tag + "] " + msg);
}

/**
 * 将字节数转为可读的大小字符串
 * @param {number} bytes - 字节数
 * @returns {string} 可读大小
 */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

/**
 * 检查给定地址处的数据是否以 DEX 魔数开头
 * @param {NativePointer} ptr - 内存地址
 * @returns {boolean} 是否匹配 DEX 魔数
 */
function isDexMagic(ptr) {
    try {
        var first4 = ptr.readU32();
        // 快速检查前 4 字节: 0x0a786564 = "dex\n" (小端序)
        if (first4 !== 0x0a786564) return false;

        // 逐一匹配完整魔数（含版本号）
        for (var m = 0; m < DEX_MAGICS.length; m++) {
            var match = true;
            for (var b = 4; b < 8; b++) {
                if (ptr.add(b).readU8() !== DEX_MAGICS[m][b]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    } catch (e) {
        // 内存不可读，忽略
    }
    return false;
}

/**
 * 解析并校验 DEX 头部，返回 file_size；不合法时返回 0
 *
 * DEX 头部布局（部分关键字段）:
 *   偏移 0x00 : magic        (8 bytes)
 *   偏移 0x08 : checksum     (4 bytes)
 *   偏移 0x0C : signature    (20 bytes)
 *   偏移 0x20 : file_size    (4 bytes)
 *   偏移 0x24 : header_size  (4 bytes)
 *   偏移 0x28 : endian_tag   (4 bytes)
 *
 * @param {NativePointer} ptr - DEX 起始地址
 * @returns {number} file_size，若不合法则返回 0
 */
function parseDexHeader(ptr) {
    try {
        var fileSize = ptr.add(0x20).readU32();
        var headerSize = ptr.add(0x24).readU32();
        var endianTag = ptr.add(0x28).readU32();

        // 校验 header_size，标准 DEX 头部为 0x70 字节
        if (headerSize !== 0x70) return 0;

        // 校验字节序标记：0x12345678 (标准) 或 0x78563412 (反转)
        if (endianTag !== 0x12345678 && endianTag !== 0x78563412) return 0;

        // 校验 file_size 在合理范围内
        if (fileSize < config.minDexSize || fileSize > config.maxDexSize) return 0;

        // 额外校验：string_ids_size 和 type_ids_size 应大于 0
        var stringIdsSize = ptr.add(0x38).readU32();
        var typeIdsSize = ptr.add(0x40).readU32();
        if (stringIdsSize === 0 || typeIdsSize === 0) return 0;

        return fileSize;
    } catch (e) {
        return 0;
    }
}

/**
 * 检查某个地址是否已经被记录过（避免重复导出）
 * @param {NativePointer} addr - 待检查地址
 * @returns {boolean} 是否已记录
 */
function isAlreadyFound(addr) {
    var addrStr = addr.toString();
    for (var i = 0; i < dexFound.length; i++) {
        if (dexFound[i].base === addrStr) return true;
    }
    return false;
}

/**
 * 导出 DEX 数据：通过 send() 发送给宿主端
 * @param {NativePointer} base - DEX 起始地址
 * @param {number} size - DEX 文件大小
 * @param {string} source - 发现来源（magic / deep_search）
 */
function dumpDex(base, size, source) {
    if (isAlreadyFound(base)) {
        log("跳过", "地址 " + base + " 已导出，跳过重复");
        return;
    }

    try {
        var dexBytes = base.readByteArray(size);
        if (!dexBytes) {
            log("错误", "无法读取地址 " + base + " 处的 " + formatSize(size) + " 数据");
            return;
        }

        var info = {
            type: "dex",
            index: dexIndex,
            size: size,
            base: base.toString()
        };

        // 发送 DEX 数据到宿主
        send(info, dexBytes);

        // 记录已导出信息
        dexFound.push({
            index: dexIndex,
            base: base.toString(),
            size: size,
            sizeHuman: formatSize(size),
            source: source
        });

        log("导出", "DEX #" + dexIndex + " | 地址: " + base +
            " | 大小: " + formatSize(size) +
            " | 来源: " + source);

        dexIndex++;
    } catch (e) {
        log("错误", "导出 DEX 失败 @ " + base + ": " + e.message);
    }
}

// ============================================================================
// 加固检测
// ============================================================================

/**
 * 检测已加载的加固方案
 * 通过枚举进程中已加载的模块名称来匹配加固特征
 */
function detectPackers() {
    log("检测", "========== 加固方案检测 ==========");
    var modules = Process.enumerateModules();
    var detected = [];

    for (var packerName in PACKER_SIGNATURES) {
        var signatures = PACKER_SIGNATURES[packerName];
        for (var s = 0; s < signatures.length; s++) {
            for (var m = 0; m < modules.length; m++) {
                if (modules[m].name.indexOf(signatures[s]) !== -1) {
                    detected.push(packerName);
                    log("检测", "发现加固: " + packerName + " (特征: " + signatures[s] + ")");
                    break;
                }
            }
            // 找到一个特征就跳到下一个加固方案
            if (detected.indexOf(packerName) !== -1) break;
        }
    }

    if (detected.length === 0) {
        log("检测", "未检测到已知加固方案（可能是未知壳或未加固）");
    }
    log("检测", "==================================");
    return detected;
}

// ============================================================================
// 内存扫描
// ============================================================================

/**
 * 扫描所有可读内存区域，搜索 DEX 文件
 * 通过 DEX 魔数进行标准搜索
 */
function scanMemoryForDex() {
    log("扫描", "开始枚举可读内存区域...");
    var ranges = Process.enumerateRanges("r--");
    log("扫描", "共发现 " + ranges.length + " 个可读内存区域");

    for (var r = 0; r < ranges.length; r++) {
        var range = ranges[r];
        scannedRanges++;

        // 跳过过小的区域（至少能容纳一个 DEX 头部）
        if (range.size < config.minDexSize) continue;

        try {
            // 在当前内存区域中搜索 DEX 魔数: "dex\n"
            var pattern = "64 65 78 0a 30 33";
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function (address, size) {
                    try {
                        // 验证完整魔数
                        if (!isDexMagic(address)) return;

                        // 解析 DEX 头部
                        var fileSize = parseDexHeader(address);
                        if (fileSize === 0) return;

                        // 确保 DEX 数据在当前内存区域内
                        var offset = address.sub(range.base).toInt32();
                        if (offset + fileSize > range.size) {
                            // DEX 可能跨区域，尝试直接读取
                            log("警告", "DEX @ " + address + " 可能跨越内存区域边界，尝试读取...");
                        }

                        dumpDex(address, fileSize, "magic");
                    } catch (e) {
                        // 单次匹配失败不影响后续搜索
                    }
                },
                onComplete: function () {}
            });
        } catch (e) {
            // 某些内存区域可能无法扫描，静默跳过
        }
    }
}

/**
 * 深度搜索：针对魔数被抹零或篡改的 DEX
 *
 * 原理：DEX 文件尾部包含 map_list 结构，其第一个条目的 type 通常为
 * TYPE_HEADER_ITEM (0x0000)，且 size 为 1，offset 为 0。
 * 通过搜索 header_size (0x70000000) 特征来定位潜在的 DEX 头部。
 *
 * 另外还会搜索 endian_tag (0x12345678) 作为辅助定位。
 */
function deepSearchDex() {
    if (!config.deepSearch) {
        log("深搜", "深度搜索已禁用，跳过");
        return;
    }

    log("深搜", "========== 深度搜索模式 ==========");
    log("深搜", "搜索被抹除魔数的 DEX 文件...");

    var ranges = Process.enumerateRanges("r--");

    for (var r = 0; r < ranges.length; r++) {
        var range = ranges[r];
        if (range.size < config.minDexSize) continue;

        try {
            // 搜索 DEX 头部特征：header_size = 0x70 (偏移 0x24)
            // 紧跟 endian_tag = 0x12345678 (偏移 0x28)
            // 即在内存中搜索连续的 70 00 00 00 78 56 34 12
            var pattern = "70 00 00 00 78 56 34 12";
            Memory.scan(range.base, range.size, pattern, {
                onMatch: function (address, size) {
                    try {
                        // 匹配到的是偏移 0x24 的位置，回退得到 DEX 起始地址
                        var dexBase = address.sub(0x24);

                        // 跳过已发现的
                        if (isAlreadyFound(dexBase)) return;

                        // 确保基地址在当前区域内
                        if (dexBase.compare(range.base) < 0) return;

                        // 读取 file_size 进行校验
                        var fileSize = dexBase.add(0x20).readU32();
                        if (fileSize < config.minDexSize || fileSize > config.maxDexSize) return;

                        // 校验 string_ids 和 type_ids
                        var stringIdsSize = dexBase.add(0x38).readU32();
                        var typeIdsSize = dexBase.add(0x40).readU32();
                        if (stringIdsSize === 0 || typeIdsSize === 0) return;

                        log("深搜", "通过头部特征定位到潜在 DEX @ " + dexBase);
                        dumpDex(dexBase, fileSize, "deep_search");
                    } catch (e) {
                        // 忽略单次错误
                    }
                },
                onComplete: function () {}
            });
        } catch (e) {
            // 静默跳过不可扫描的区域
        }
    }

    log("深搜", "深度搜索完成");
}

// ============================================================================
// 主流程
// ============================================================================

/**
 * 主入口函数
 * 流程：检测加固 → 等待加载 → 标准扫描 → 深度搜索 → 输出汇总
 */
function main() {
    log("主程", "====================================================");
    log("主程", "       Frida DEX 内存转储工具 v1.0");
    log("主程", "====================================================");
    log("主程", "进程名: " + Process.id + " (" + (Process.arch) + ")");
    log("主程", "配置 - 最小DEX: " + formatSize(config.minDexSize));
    log("主程", "配置 - 最大DEX: " + formatSize(config.maxDexSize));
    log("主程", "配置 - 深度搜索: " + (config.deepSearch ? "启用" : "禁用"));
    log("主程", "配置 - 等待时间: " + config.waitSeconds + " 秒");
    log("主程", "====================================================");

    // 第一步：检测加固方案
    detectPackers();

    // 第二步：等待应用完全加载
    log("主程", "等待 " + config.waitSeconds + " 秒，让应用完成初始化和脱壳...");

    setTimeout(function () {
        try {
            // 使用 Java.perform 确保在 Java 运行时上下文中操作
            Java.perform(function () {
                log("主程", "Java 运行时已就绪，开始扫描内存...");

                // 第三步：标准扫描（魔数匹配）
                log("扫描", "========== 标准扫描模式 ==========");
                scanMemoryForDex();
                log("扫描", "标准扫描完成，已扫描 " + scannedRanges + " 个内存区域");

                // 第四步：深度搜索（针对魔数被破坏的情况）
                deepSearchDex();

                // 第五步：输出汇总报告
                log("汇总", "====================================================");
                log("汇总", "           扫描结果汇总");
                log("汇总", "====================================================");
                log("汇总", "扫描内存区域数: " + scannedRanges);
                log("汇总", "发现 DEX 文件数: " + dexFound.length);

                if (dexFound.length > 0) {
                    log("汇总", "----------------------------------------------------");
                    for (var i = 0; i < dexFound.length; i++) {
                        var d = dexFound[i];
                        log("汇总", "  #" + d.index +
                            " | 基址: " + d.base +
                            " | 大小: " + d.sizeHuman +
                            " | 来源: " + d.source);
                    }
                    log("汇总", "----------------------------------------------------");
                    log("汇总", "提示: 请在宿主端接收并保存 DEX 文件");
                } else {
                    log("汇总", "未发现任何 DEX 文件。建议：");
                    log("汇总", "  1. 增加 waitSeconds 等待时间");
                    log("汇总", "  2. 确认应用已完全启动并完成脱壳");
                    log("汇总", "  3. 尝试手动触发应用功能后重新扫描");
                }
                log("汇总", "====================================================");
            });
        } catch (e) {
            log("错误", "Java.perform 执行失败: " + e.message);
            log("错误", "回退到纯 Native 模式扫描...");

            // 回退：不依赖 Java 运行时，直接进行内存扫描
            scanMemoryForDex();
            deepSearchDex();

            log("汇总", "扫描完成，共发现 " + dexFound.length + " 个 DEX 文件");
        }
    }, config.waitSeconds * 1000);
}

// ============================================================================
// 启动入口
// ============================================================================
if (config.autoStart) {
    log("启动", "autoStart 已启用，即将开始...");
    main();
} else {
    log("启动", "autoStart 已禁用，请手动调用 main() 启动扫描");
    // 导出 main 函数供手动调用
    rpc.exports = {
        start: main
    };
}
