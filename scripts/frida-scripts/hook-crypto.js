/**
 * Frida 加密函数 Hook 脚本 - 用于算法还原
 *
 * 功能：拦截 Android/Java 中常见的加密操作，捕获密钥、IV、明文、密文等信息
 * 支持：Cipher (AES/DES/RSA等)、MessageDigest (MD5/SHA等)、Mac (HMAC)、Signature (数字签名)
 */

'use strict';

// ==================== 配置区域 ====================
var CONFIG = {
    hookCipher: true,          // 是否 Hook javax.crypto.Cipher
    hookDigest: true,          // 是否 Hook java.security.MessageDigest
    hookMac: true,             // 是否 Hook javax.crypto.Mac
    hookSignature: true,       // 是否 Hook java.security.Signature
    verbose: false,            // 详细模式：输出更多调试信息
    maxDataLength: 256,        // 日志中数据最大显示长度（字节），超出则截断
    stackTraceDepth: 15        // 堆栈跟踪最大深度
};

// ==================== 辅助函数 ====================

/**
 * 字节数组转十六进制字符串
 * @param {byte[]} bytes - Java 字节数组
 * @returns {string} 十六进制字符串
 */
function bytesToHex(bytes) {
    if (bytes === null || bytes === undefined) {
        return '';
    }
    try {
        var len = bytes.length;
        var hex = [];
        for (var i = 0; i < len; i++) {
            var b = (bytes[i] & 0xFF);
            hex.push(('0' + b.toString(16)).slice(-2));
        }
        return hex.join('');
    } catch (e) {
        return '<error: ' + e.message + '>';
    }
}

/**
 * 字节数组转 Base64 字符串
 * @param {byte[]} bytes - Java 字节数组
 * @returns {string} Base64 编码字符串
 */
function bytesToBase64(bytes) {
    if (bytes === null || bytes === undefined) {
        return '';
    }
    try {
        var Base64 = Java.use('android.util.Base64');
        return Base64.encodeToString(bytes, 2 /* NO_WRAP */);
    } catch (e) {
        // 回退方案：手动编码
        try {
            var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
            var result = '';
            var len = bytes.length;
            for (var i = 0; i < len; i += 3) {
                var b0 = bytes[i] & 0xFF;
                var b1 = (i + 1 < len) ? (bytes[i + 1] & 0xFF) : 0;
                var b2 = (i + 2 < len) ? (bytes[i + 2] & 0xFF) : 0;
                result += charset[(b0 >> 2) & 0x3F];
                result += charset[((b0 << 4) | (b1 >> 4)) & 0x3F];
                result += (i + 1 < len) ? charset[((b1 << 2) | (b2 >> 6)) & 0x3F] : '=';
                result += (i + 2 < len) ? charset[b2 & 0x3F] : '=';
            }
            return result;
        } catch (e2) {
            return '<error: ' + e2.message + '>';
        }
    }
}

/**
 * 获取 Java 调用堆栈
 * @returns {string} 格式化的堆栈跟踪字符串
 */
function getStackTrace() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var e = Exception.$new();
        var stackElements = e.getStackTrace();
        var lines = [];
        var depth = Math.min(stackElements.length, CONFIG.stackTraceDepth);
        for (var i = 0; i < depth; i++) {
            lines.push('    at ' + stackElements[i].toString());
        }
        if (stackElements.length > CONFIG.stackTraceDepth) {
            lines.push('    ... 省略 ' + (stackElements.length - CONFIG.stackTraceDepth) + ' 行');
        }
        return lines.join('\n');
    } catch (e) {
        return '<无法获取堆栈>';
    }
}

/**
 * 将 Cipher 模式常量转为可读字符串
 * @param {number} mode - Cipher 模式常量
 * @returns {string} 模式名称
 */
function getModeString(mode) {
    switch (mode) {
        case 1: return 'ENCRYPT';
        case 2: return 'DECRYPT';
        case 3: return 'WRAP';
        case 4: return 'UNWRAP';
        default: return 'UNKNOWN(' + mode + ')';
    }
}

/**
 * 对过长的数据进行截断处理
 * @param {string} hexStr - 十六进制字符串
 * @returns {string} 截断后的字符串
 */
function truncateData(hexStr) {
    if (!hexStr) return '';
    var maxHexLen = CONFIG.maxDataLength * 2;
    if (hexStr.length > maxHexLen) {
        return hexStr.substring(0, maxHexLen) + '...(truncated, total ' + (hexStr.length / 2) + ' bytes)';
    }
    return hexStr;
}

/**
 * 构造并输出 JSON 日志
 * @param {object} info - 加密操作信息对象
 */
function emitLog(info) {
    var log = {
        type: 'crypto',
        timestamp: new Date().toISOString(),
        operation: info.operation || '',
        algorithm: info.algorithm || '',
    };

    if (info.mode !== undefined) {
        log.mode = info.mode;
    }
    if (info.key) {
        log.key = {};
        if (info.key.hex) log.key.hex = truncateData(info.key.hex);
        if (info.key.base64) log.key.base64 = info.key.base64;
    }
    if (info.iv) {
        log.iv = { hex: truncateData(info.iv.hex) };
    }
    if (info.input) {
        log.input = {
            hex: truncateData(info.input.hex),
            length: info.input.length
        };
    }
    if (info.output) {
        log.output = {
            hex: truncateData(info.output.hex),
            length: info.output.length
        };
    }

    log.stackTrace = getStackTrace();

    // 使用 send() 发送 JSON 到主控端，同时用 console.log 打印可读格式
    send(log);
    console.log('\n[CryptoHook] ===== ' + log.operation + ' =====');
    console.log(JSON.stringify(log, null, 2));
}

// ==================== 用于跟踪 Cipher 实例状态的映射 ====================
// 存储每个 Cipher 实例的 init 信息（算法、模式、密钥、IV）
var cipherStateMap = {};

/**
 * 获取或分配 Cipher 实例的跟踪 ID
 */
function getCipherId(cipherInstance) {
    try {
        var System = Java.use('java.lang.System');
        return System.identityHashCode(cipherInstance);
    } catch (e) {
        return 'fallback_' + Date.now() + '_' + Math.random();
    }
}

// ==================== Hook 入口 ====================
Java.perform(function () {
    console.log('[CryptoHook] 脚本加载中...');
    console.log('[CryptoHook] 配置: ' + JSON.stringify(CONFIG));

    // ==================== 1. Hook SecretKeySpec 构造函数 ====================
    if (CONFIG.hookCipher) {
        try {
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

            // SecretKeySpec(byte[] key, String algorithm)
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algorithm) {
                emitLog({
                    operation: 'SecretKeySpec.<init>',
                    algorithm: algorithm,
                    key: {
                        hex: bytesToHex(key),
                        base64: bytesToBase64(key)
                    }
                });
                return this.$init(key, algorithm);
            };

            // SecretKeySpec(byte[] key, int offset, int len, String algorithm)
            SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (key, offset, len, algorithm) {
                emitLog({
                    operation: 'SecretKeySpec.<init>',
                    algorithm: algorithm,
                    key: {
                        hex: bytesToHex(key),
                        base64: bytesToBase64(key)
                    },
                    input: {
                        hex: '(offset=' + offset + ', len=' + len + ')',
                        length: len
                    }
                });
                return this.$init(key, offset, len, algorithm);
            };

            console.log('[CryptoHook] SecretKeySpec Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] SecretKeySpec Hook 失败: ' + e.message);
        }
    }

    // ==================== 2. Hook IvParameterSpec 构造函数 ====================
    if (CONFIG.hookCipher) {
        try {
            var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

            // IvParameterSpec(byte[] iv)
            IvParameterSpec.$init.overload('[B').implementation = function (iv) {
                emitLog({
                    operation: 'IvParameterSpec.<init>',
                    iv: { hex: bytesToHex(iv) }
                });
                return this.$init(iv);
            };

            // IvParameterSpec(byte[] iv, int offset, int len)
            IvParameterSpec.$init.overload('[B', 'int', 'int').implementation = function (iv, offset, len) {
                emitLog({
                    operation: 'IvParameterSpec.<init>',
                    iv: { hex: bytesToHex(iv) },
                    input: {
                        hex: '(offset=' + offset + ', len=' + len + ')',
                        length: len
                    }
                });
                return this.$init(iv, offset, len);
            };

            console.log('[CryptoHook] IvParameterSpec Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] IvParameterSpec Hook 失败: ' + e.message);
        }
    }

    // ==================== 3. Hook Cipher ====================
    if (CONFIG.hookCipher) {
        try {
            var Cipher = Java.use('javax.crypto.Cipher');

            // --- Cipher.init() 所有重载 ---
            // init(int opmode, Key key)
            Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
                var id = getCipherId(this);
                var algo = this.getAlgorithm();
                var keyBytes = key.getEncoded();
                cipherStateMap[id] = {
                    algorithm: algo,
                    mode: getModeString(opmode),
                    keyHex: bytesToHex(keyBytes),
                    keyBase64: bytesToBase64(keyBytes)
                };
                emitLog({
                    operation: 'Cipher.init',
                    algorithm: algo,
                    mode: getModeString(opmode),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    }
                });
                return this.init(opmode, key);
            };

            // init(int opmode, Key key, AlgorithmParameterSpec params)
            Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
                var id = getCipherId(this);
                var algo = this.getAlgorithm();
                var keyBytes = key.getEncoded();
                var ivHex = '';
                // 尝试从参数中提取 IV
                try {
                    var ivSpec = Java.cast(params, Java.use('javax.crypto.spec.IvParameterSpec'));
                    ivHex = bytesToHex(ivSpec.getIV());
                } catch (e) {
                    if (CONFIG.verbose) {
                        console.log('[CryptoHook] 参数非 IvParameterSpec，可能是 GCMParameterSpec 等');
                    }
                    // 尝试 GCMParameterSpec
                    try {
                        var gcmSpec = Java.cast(params, Java.use('javax.crypto.spec.GCMParameterSpec'));
                        ivHex = bytesToHex(gcmSpec.getIV());
                    } catch (e2) { /* 忽略 */ }
                }
                cipherStateMap[id] = {
                    algorithm: algo,
                    mode: getModeString(opmode),
                    keyHex: bytesToHex(keyBytes),
                    keyBase64: bytesToBase64(keyBytes),
                    ivHex: ivHex
                };
                emitLog({
                    operation: 'Cipher.init',
                    algorithm: algo,
                    mode: getModeString(opmode),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    },
                    iv: { hex: ivHex }
                });
                return this.init(opmode, key, params);
            };

            // init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function (opmode, key, params, random) {
                var id = getCipherId(this);
                var algo = this.getAlgorithm();
                var keyBytes = key.getEncoded();
                var ivHex = '';
                try {
                    var ivSpec = Java.cast(params, Java.use('javax.crypto.spec.IvParameterSpec'));
                    ivHex = bytesToHex(ivSpec.getIV());
                } catch (e) {
                    try {
                        var gcmSpec = Java.cast(params, Java.use('javax.crypto.spec.GCMParameterSpec'));
                        ivHex = bytesToHex(gcmSpec.getIV());
                    } catch (e2) { /* 忽略 */ }
                }
                cipherStateMap[id] = {
                    algorithm: algo,
                    mode: getModeString(opmode),
                    keyHex: bytesToHex(keyBytes),
                    keyBase64: bytesToBase64(keyBytes),
                    ivHex: ivHex
                };
                emitLog({
                    operation: 'Cipher.init',
                    algorithm: algo,
                    mode: getModeString(opmode),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    },
                    iv: { hex: ivHex }
                });
                return this.init(opmode, key, params, random);
            };

            // init(int opmode, Key key, SecureRandom random)
            Cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function (opmode, key, random) {
                var id = getCipherId(this);
                var algo = this.getAlgorithm();
                var keyBytes = key.getEncoded();
                cipherStateMap[id] = {
                    algorithm: algo,
                    mode: getModeString(opmode),
                    keyHex: bytesToHex(keyBytes),
                    keyBase64: bytesToBase64(keyBytes)
                };
                emitLog({
                    operation: 'Cipher.init',
                    algorithm: algo,
                    mode: getModeString(opmode),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    }
                });
                return this.init(opmode, key, random);
            };

            // --- Cipher.update() 所有重载 ---
            // update(byte[] input)
            Cipher.update.overload('[B').implementation = function (input) {
                var id = getCipherId(this);
                var state = cipherStateMap[id] || {};
                emitLog({
                    operation: 'Cipher.update',
                    algorithm: state.algorithm || this.getAlgorithm(),
                    mode: state.mode || '',
                    input: { hex: bytesToHex(input), length: input.length }
                });
                return this.update(input);
            };

            // update(byte[] input, int inputOffset, int inputLen)
            Cipher.update.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
                var id = getCipherId(this);
                var state = cipherStateMap[id] || {};
                emitLog({
                    operation: 'Cipher.update',
                    algorithm: state.algorithm || this.getAlgorithm(),
                    mode: state.mode || '',
                    input: { hex: bytesToHex(input), length: len }
                });
                return this.update(input, offset, len);
            };

            // --- Cipher.doFinal() 所有重载 ---
            // doFinal()
            Cipher.doFinal.overload().implementation = function () {
                var id = getCipherId(this);
                var state = cipherStateMap[id] || {};
                var result = this.doFinal();
                emitLog({
                    operation: 'Cipher.doFinal',
                    algorithm: state.algorithm || this.getAlgorithm(),
                    mode: state.mode || '',
                    key: state.keyHex ? { hex: state.keyHex, base64: state.keyBase64 } : undefined,
                    iv: state.ivHex ? { hex: state.ivHex } : undefined,
                    output: { hex: bytesToHex(result), length: result.length }
                });
                delete cipherStateMap[id];
                return result;
            };

            // doFinal(byte[] input)
            Cipher.doFinal.overload('[B').implementation = function (input) {
                var id = getCipherId(this);
                var state = cipherStateMap[id] || {};
                var result = this.doFinal(input);
                emitLog({
                    operation: 'Cipher.doFinal',
                    algorithm: state.algorithm || this.getAlgorithm(),
                    mode: state.mode || '',
                    key: state.keyHex ? { hex: state.keyHex, base64: state.keyBase64 } : undefined,
                    iv: state.ivHex ? { hex: state.ivHex } : undefined,
                    input: { hex: bytesToHex(input), length: input.length },
                    output: { hex: bytesToHex(result), length: result.length }
                });
                delete cipherStateMap[id];
                return result;
            };

            // doFinal(byte[] input, int inputOffset, int inputLen)
            Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
                var id = getCipherId(this);
                var state = cipherStateMap[id] || {};
                var result = this.doFinal(input, offset, len);
                emitLog({
                    operation: 'Cipher.doFinal',
                    algorithm: state.algorithm || this.getAlgorithm(),
                    mode: state.mode || '',
                    key: state.keyHex ? { hex: state.keyHex, base64: state.keyBase64 } : undefined,
                    iv: state.ivHex ? { hex: state.ivHex } : undefined,
                    input: { hex: bytesToHex(input), length: len },
                    output: { hex: bytesToHex(result), length: result.length }
                });
                delete cipherStateMap[id];
                return result;
            };

            console.log('[CryptoHook] Cipher Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] Cipher Hook 失败: ' + e.message);
        }
    }

    // ==================== 4. Hook MessageDigest ====================
    if (CONFIG.hookDigest) {
        try {
            var MessageDigest = Java.use('java.security.MessageDigest');

            // getInstance(String algorithm)
            MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
                if (CONFIG.verbose) {
                    emitLog({
                        operation: 'MessageDigest.getInstance',
                        algorithm: algorithm
                    });
                }
                return this.getInstance(algorithm);
            };

            // getInstance(String algorithm, String provider)
            MessageDigest.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (algorithm, provider) {
                if (CONFIG.verbose) {
                    emitLog({
                        operation: 'MessageDigest.getInstance',
                        algorithm: algorithm + ' (provider: ' + provider + ')'
                    });
                }
                return this.getInstance(algorithm, provider);
            };

            // update(byte[] input)
            MessageDigest.update.overload('[B').implementation = function (input) {
                emitLog({
                    operation: 'MessageDigest.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: input.length }
                });
                return this.update(input);
            };

            // update(byte[] input, int offset, int len)
            MessageDigest.update.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
                emitLog({
                    operation: 'MessageDigest.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: len }
                });
                return this.update(input, offset, len);
            };

            // update(byte input) - 单字节
            MessageDigest.update.overload('byte').implementation = function (input) {
                if (CONFIG.verbose) {
                    emitLog({
                        operation: 'MessageDigest.update',
                        algorithm: this.getAlgorithm(),
                        input: { hex: ('0' + (input & 0xFF).toString(16)).slice(-2), length: 1 }
                    });
                }
                return this.update(input);
            };

            // digest() - 无参数，返回哈希结果
            MessageDigest.digest.overload().implementation = function () {
                var result = this.digest();
                emitLog({
                    operation: 'MessageDigest.digest',
                    algorithm: this.getAlgorithm(),
                    output: { hex: bytesToHex(result), length: result.length }
                });
                return result;
            };

            // digest(byte[] input) - 传入数据并返回哈希
            MessageDigest.digest.overload('[B').implementation = function (input) {
                var result = this.digest(input);
                emitLog({
                    operation: 'MessageDigest.digest',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: input.length },
                    output: { hex: bytesToHex(result), length: result.length }
                });
                return result;
            };

            console.log('[CryptoHook] MessageDigest Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] MessageDigest Hook 失败: ' + e.message);
        }
    }

    // ==================== 5. Hook Mac (HMAC) ====================
    if (CONFIG.hookMac) {
        try {
            var Mac = Java.use('javax.crypto.Mac');

            // init(Key key)
            Mac.init.overload('java.security.Key').implementation = function (key) {
                var keyBytes = key.getEncoded();
                emitLog({
                    operation: 'Mac.init',
                    algorithm: this.getAlgorithm(),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    }
                });
                return this.init(key);
            };

            // init(Key key, AlgorithmParameterSpec params)
            Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (key, params) {
                var keyBytes = key.getEncoded();
                emitLog({
                    operation: 'Mac.init',
                    algorithm: this.getAlgorithm(),
                    key: {
                        hex: bytesToHex(keyBytes),
                        base64: bytesToBase64(keyBytes)
                    }
                });
                return this.init(key, params);
            };

            // update(byte[] input)
            Mac.update.overload('[B').implementation = function (input) {
                emitLog({
                    operation: 'Mac.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: input.length }
                });
                return this.update(input);
            };

            // update(byte[] input, int offset, int len)
            Mac.update.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
                emitLog({
                    operation: 'Mac.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: len }
                });
                return this.update(input, offset, len);
            };

            // doFinal()
            Mac.doFinal.overload().implementation = function () {
                var result = this.doFinal();
                emitLog({
                    operation: 'Mac.doFinal',
                    algorithm: this.getAlgorithm(),
                    output: { hex: bytesToHex(result), length: result.length }
                });
                return result;
            };

            // doFinal(byte[] input)
            Mac.doFinal.overload('[B').implementation = function (input) {
                var result = this.doFinal(input);
                emitLog({
                    operation: 'Mac.doFinal',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(input), length: input.length },
                    output: { hex: bytesToHex(result), length: result.length }
                });
                return result;
            };

            console.log('[CryptoHook] Mac Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] Mac Hook 失败: ' + e.message);
        }
    }

    // ==================== 6. Hook Signature (数字签名) ====================
    if (CONFIG.hookSignature) {
        try {
            var Signature = Java.use('java.security.Signature');

            // initSign(PrivateKey privateKey) - 初始化签名
            Signature.initSign.overload('java.security.PrivateKey').implementation = function (privateKey) {
                emitLog({
                    operation: 'Signature.initSign',
                    algorithm: this.getAlgorithm(),
                    key: {
                        hex: bytesToHex(privateKey.getEncoded()),
                        base64: bytesToBase64(privateKey.getEncoded())
                    }
                });
                return this.initSign(privateKey);
            };

            // initSign(PrivateKey privateKey, SecureRandom random)
            Signature.initSign.overload('java.security.PrivateKey', 'java.security.SecureRandom').implementation = function (privateKey, random) {
                emitLog({
                    operation: 'Signature.initSign',
                    algorithm: this.getAlgorithm(),
                    key: {
                        hex: bytesToHex(privateKey.getEncoded()),
                        base64: bytesToBase64(privateKey.getEncoded())
                    }
                });
                return this.initSign(privateKey, random);
            };

            // initVerify(PublicKey publicKey) - 初始化验签
            Signature.initVerify.overload('java.security.PublicKey').implementation = function (publicKey) {
                emitLog({
                    operation: 'Signature.initVerify',
                    algorithm: this.getAlgorithm(),
                    key: {
                        hex: bytesToHex(publicKey.getEncoded()),
                        base64: bytesToBase64(publicKey.getEncoded())
                    }
                });
                return this.initVerify(publicKey);
            };

            // update(byte[] data) - 更新签名数据
            Signature.update.overload('[B').implementation = function (data) {
                emitLog({
                    operation: 'Signature.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(data), length: data.length }
                });
                return this.update(data);
            };

            // update(byte[] data, int off, int len)
            Signature.update.overload('[B', 'int', 'int').implementation = function (data, off, len) {
                emitLog({
                    operation: 'Signature.update',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(data), length: len }
                });
                return this.update(data, off, len);
            };

            // sign() - 执行签名
            Signature.sign.overload().implementation = function () {
                var result = this.sign();
                emitLog({
                    operation: 'Signature.sign',
                    algorithm: this.getAlgorithm(),
                    output: { hex: bytesToHex(result), length: result.length }
                });
                return result;
            };

            // verify(byte[] signature) - 验证签名
            Signature.verify.overload('[B').implementation = function (signature) {
                var result = this.verify(signature);
                emitLog({
                    operation: 'Signature.verify',
                    algorithm: this.getAlgorithm(),
                    input: { hex: bytesToHex(signature), length: signature.length },
                    output: { hex: result.toString(), length: 1 }
                });
                return result;
            };

            console.log('[CryptoHook] Signature Hook 完成');
        } catch (e) {
            console.log('[CryptoHook] Signature Hook 失败: ' + e.message);
        }
    }

    console.log('[CryptoHook] ===== 所有 Hook 已就绪 =====');
    console.log('[CryptoHook] 等待加密操作触发...');
});
