/**
 * SSL Pinning 通用绕过脚本
 * 适用于 Android 平台，支持多种 SSL Pinning 实现的绕过
 * 每个绕过模块独立运行，互不影响
 */

// ==================== 配置项 ====================
var config = {
    enableX509: true,              // 绕过 X509TrustManager 证书校验
    enableOkHttp: true,            // 绕过 OkHttp3 CertificatePinner
    enableTrustManager: true,      // 绕过 TrustManagerImpl.verifyChain (Android 7+)
    enableNetworkSecurity: true,   // 绕过 NetworkSecurityConfig (Android 7+)
    enableWebView: true,           // 绕过 WebViewClient SSL 错误拦截
    enableSSLContext: true,        // 绕过 SSLContext.init 中的 TrustManager
    enableHttpsURLConnection: true,// 绕过 HttpsURLConnection 的工厂和验证器设置
    verbose: false                 // 是否输出详细日志（包括每次调用的堆栈信息等）
};

// ==================== 日志工具 ====================
var TAG = "[SSL-Unpin]";
var successCount = 0;
var failCount = 0;
var results = [];
var _ts = Date.now();  // 时间戳后缀，防止重复注入时类名冲突

function log(msg) {
    console.log(TAG + " " + msg);
}

function logVerbose(msg) {
    if (config.verbose) {
        console.log(TAG + " [VERBOSE] " + msg);
    }
}

function recordSuccess(name) {
    successCount++;
    results.push({ name: name, status: "SUCCESS" });
    log("[+] " + name + " 绕过安装成功");
}

function recordFailure(name, err) {
    failCount++;
    results.push({ name: name, status: "FAILED", error: err.toString() });
    log("[-] " + name + " 绕过安装失败: " + err);
}

// ==================== 主逻辑 ====================
Java.perform(function () {
    log("========================================");
    log("SSL Pinning 通用绕过脚本启动");
    log("========================================");

    // ------------------------------------------
    // 1. X509TrustManager 绕过
    //    创建一个空的 TrustManager 实现，信任所有证书
    // ------------------------------------------
    if (config.enableX509) {
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            // 创建自定义 TrustManager，所有方法均为空实现
            var TrustManager = Java.registerClass({
                name: "com.sslunpin.EmptyTrustManager_" + _ts,
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {
                        logVerbose("X509TrustManager.checkClientTrusted 被调用，已放行");
                    },
                    checkServerTrusted: function (chain, authType) {
                        logVerbose("X509TrustManager.checkServerTrusted 被调用，已放行");
                    },
                    getAcceptedIssuers: function () {
                        logVerbose("X509TrustManager.getAcceptedIssuers 被调用，返回空数组");
                        return [];
                    }
                }
            });

            // 将自定义 TrustManager 保存到全局，供其他模块使用
            var emptyTrustManager = TrustManager.$new();
            var emptyTrustManagerArray = Java.array("javax.net.ssl.TrustManager", [emptyTrustManager]);

            recordSuccess("X509TrustManager");
        } catch (e) {
            recordFailure("X509TrustManager", e);
        }
    }

    // ------------------------------------------
    // 2. OkHttp3 CertificatePinner 绕过
    //    Hook check 和 check$okhttp 方法的所有重载
    // ------------------------------------------
    if (config.enableOkHttp) {
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");

            // 绕过 check 方法（所有重载）
            if (CertificatePinner.check) {
                var checkOverloads = CertificatePinner.check.overloads;
                for (var i = 0; i < checkOverloads.length; i++) {
                    checkOverloads[i].implementation = function () {
                        logVerbose("OkHttp3 CertificatePinner.check 被调用，已绕过，参数: " + arguments[0]);
                        return;
                    };
                }
                log("  -> check 方法已 Hook (" + checkOverloads.length + " 个重载)");
            }

            // 绕过 check$okhttp 方法（Kotlin 编译后的方法名，所有重载）
            if (CertificatePinner["check$okhttp"]) {
                var checkOkhttpOverloads = CertificatePinner["check$okhttp"].overloads;
                for (var j = 0; j < checkOkhttpOverloads.length; j++) {
                    checkOkhttpOverloads[j].implementation = function () {
                        logVerbose("OkHttp3 CertificatePinner.check$okhttp 被调用，已绕过，参数: " + arguments[0]);
                        return;
                    };
                }
                log("  -> check$okhttp 方法已 Hook (" + checkOkhttpOverloads.length + " 个重载)");
            }

            recordSuccess("OkHttp3 CertificatePinner");
        } catch (e) {
            recordFailure("OkHttp3 CertificatePinner", e);
        }
    }

    // ------------------------------------------
    // 3. TrustManagerImpl.verifyChain 绕过 (Android 7+)
    //    直接返回传入的证书链，跳过系统校验
    // ------------------------------------------
    if (config.enableTrustManager) {
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

            // verifyChain 负责验证证书链的有效性
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                logVerbose("TrustManagerImpl.verifyChain 被调用，目标主机: " + host + "，已绕过");
                return untrustedChain;
            };

            recordSuccess("TrustManagerImpl.verifyChain");
        } catch (e) {
            // 某些 Android 版本方法签名不同，尝试备用签名
            try {
                var TrustManagerImplAlt = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                var verifyOverloads = TrustManagerImplAlt.checkTrustedRecursive.overloads;
                for (var k = 0; k < verifyOverloads.length; k++) {
                    verifyOverloads[k].implementation = function () {
                        logVerbose("TrustManagerImpl.checkTrustedRecursive 被调用，已绕过");
                        return Java.use("java.util.ArrayList").$new();
                    };
                }
                recordSuccess("TrustManagerImpl.checkTrustedRecursive (备用)");
            } catch (e2) {
                recordFailure("TrustManagerImpl.verifyChain", e2);
            }
        }
    }

    // ------------------------------------------
    // 4. NetworkSecurityConfig 绕过 (Android 7+)
    //    让系统认为所有网络配置都允许明文和用户证书
    // ------------------------------------------
    if (config.enableNetworkSecurity) {
        try {
            // 绕过 NetworkSecurityTrustManager 的证书校验
            var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");

            NetworkSecurityTrustManager.checkServerTrusted.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    logVerbose("NetworkSecurityTrustManager.checkServerTrusted 被调用，已绕过");
                    return;
                };
            });

            recordSuccess("NetworkSecurityConfig (TrustManager)");
        } catch (e) {
            recordFailure("NetworkSecurityConfig (TrustManager)", e);
        }

        // 单独 try/catch 处理 RootTrustManager，避免影响上面的绕过
        try {
            var RootTrustManager = Java.use("android.security.net.config.RootTrustManager");

            RootTrustManager.checkServerTrusted.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    logVerbose("RootTrustManager.checkServerTrusted 被调用，已绕过");
                    return;
                };
            });

            recordSuccess("NetworkSecurityConfig (RootTrustManager)");
        } catch (e) {
            recordFailure("NetworkSecurityConfig (RootTrustManager)", e);
        }

        // 绕过 ManifestConfigSource 使应用认为不存在 network_security_config
        try {
            var ManifestConfigSource = Java.use("android.security.net.config.ManifestConfigSource");

            ManifestConfigSource.getConfigSource.implementation = function () {
                logVerbose("ManifestConfigSource.getConfigSource 被调用，返回默认配置");
                // 使用默认的配置源，允许用户证书
                var DefaultConfigSource = Java.use("android.security.net.config.DefaultConfigSource");
                var argTrue = Java.use("java.lang.Boolean").TRUE.value;
                return DefaultConfigSource.$new(argTrue);
            };

            recordSuccess("NetworkSecurityConfig (ManifestConfigSource)");
        } catch (e) {
            // ManifestConfigSource 可能不存在于所有设备上，不记录为失败
            logVerbose("NetworkSecurityConfig (ManifestConfigSource) 不可用: " + e);
        }
    }

    // ------------------------------------------
    // 5. WebViewClient.onReceivedSslError 绕过
    //    自动调用 handler.proceed() 忽略 SSL 错误
    // ------------------------------------------
    if (config.enableWebView) {
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");

            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                logVerbose("WebViewClient.onReceivedSslError 被调用，SSL 错误: " + error.toString() + "，自动放行");
                // 调用 proceed 忽略 SSL 错误，继续加载页面
                handler.proceed();
            };

            recordSuccess("WebViewClient.onReceivedSslError");
        } catch (e) {
            recordFailure("WebViewClient.onReceivedSslError", e);
        }

    }

    // ------------------------------------------
    // 6. SSLContext.init 绕过
    //    替换 TrustManager 数组，注入空实现的 TrustManager
    // ------------------------------------------
    if (config.enableSSLContext) {
        try {
            var SSLContextClass = Java.use("javax.net.ssl.SSLContext");

            SSLContextClass.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            ).implementation = function (keyManager, trustManager, secureRandom) {
                logVerbose("SSLContext.init 被调用，替换 TrustManager 数组为空实现");

                // 创建信任所有证书的 TrustManager
                var X509TrustManagerForSSL = Java.use("javax.net.ssl.X509TrustManager");
                var EmptyTrustManagerForSSL = Java.registerClass({
                    name: "com.sslunpin.SSLContextTrustManager_" + _ts,
                    implements: [X509TrustManagerForSSL],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {},
                        getAcceptedIssuers: function () {
                            return [];
                        }
                    }
                });

                var customTrustManager = Java.array(
                    "javax.net.ssl.TrustManager",
                    [EmptyTrustManagerForSSL.$new()]
                );

                // 使用自定义的 TrustManager 替换原始参数
                this.init(keyManager, customTrustManager, secureRandom);
            };

            recordSuccess("SSLContext.init");
        } catch (e) {
            recordFailure("SSLContext.init", e);
        }
    }

    // ------------------------------------------
    // 7. HttpsURLConnection 绕过
    //    Hook setSSLSocketFactory 和 setHostnameVerifier
    //    使其使用信任所有证书的工厂和验证器
    // ------------------------------------------
    if (config.enableHttpsURLConnection) {
        // 绕过 setSSLSocketFactory
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

            HttpsURLConnection.setSSLSocketFactory.implementation = function (factory) {
                logVerbose("HttpsURLConnection.setSSLSocketFactory 被调用，替换为信任所有证书的工厂");

                // 创建信任所有证书的 SSLSocketFactory
                var TrustAllManager = Java.use("javax.net.ssl.X509TrustManager");
                var EmptyTM = Java.registerClass({
                    name: "com.sslunpin.HttpsTrustManager_" + _ts,
                    implements: [TrustAllManager],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {},
                        getAcceptedIssuers: function () {
                            return [];
                        }
                    }
                });

                var sslCtx = Java.use("javax.net.ssl.SSLContext").getInstance("TLS");
                var tmArray = Java.array("javax.net.ssl.TrustManager", [EmptyTM.$new()]);
                sslCtx.init(null, tmArray, null);

                // 使用自定义的 SSLSocketFactory
                this.setSSLSocketFactory(sslCtx.getSocketFactory());
            };

            recordSuccess("HttpsURLConnection.setSSLSocketFactory");
        } catch (e) {
            recordFailure("HttpsURLConnection.setSSLSocketFactory", e);
        }

        // 绕过 setHostnameVerifier
        try {
            var HttpsURLConnection2 = Java.use("javax.net.ssl.HttpsURLConnection");

            HttpsURLConnection2.setHostnameVerifier.implementation = function (verifier) {
                logVerbose("HttpsURLConnection.setHostnameVerifier 被调用，替换为信任所有主机的验证器");

                // 创建信任所有主机名的 HostnameVerifier
                var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
                var AllowAllHostnameVerifier = Java.registerClass({
                    name: "com.sslunpin.AllowAllHostnameVerifier_" + _ts,
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function (hostname, session) {
                            logVerbose("HostnameVerifier.verify 被调用，主机: " + hostname + "，已放行");
                            return true;
                        }
                    }
                });

                this.setHostnameVerifier(AllowAllHostnameVerifier.$new());
            };

            recordSuccess("HttpsURLConnection.setHostnameVerifier");
        } catch (e) {
            recordFailure("HttpsURLConnection.setHostnameVerifier", e);
        }

        // 同时 Hook 静态的 setDefaultSSLSocketFactory 和 setDefaultHostnameVerifier
        try {
            var HttpsURLConnection3 = Java.use("javax.net.ssl.HttpsURLConnection");

            HttpsURLConnection3.setDefaultHostnameVerifier.implementation = function (verifier) {
                logVerbose("HttpsURLConnection.setDefaultHostnameVerifier 被调用，已拦截并替换");

                var HostnameVerifierDefault = Java.use("javax.net.ssl.HostnameVerifier");
                var AllowAllDefault = Java.registerClass({
                    name: "com.sslunpin.AllowAllDefaultHostnameVerifier_" + _ts,
                    implements: [HostnameVerifierDefault],
                    methods: {
                        verify: function (hostname, session) {
                            return true;
                        }
                    }
                });

                this.setDefaultHostnameVerifier(AllowAllDefault.$new());
            };

            recordSuccess("HttpsURLConnection.setDefaultHostnameVerifier");
        } catch (e) {
            recordFailure("HttpsURLConnection.setDefaultHostnameVerifier", e);
        }

        try {
            var HttpsURLConnection4 = Java.use("javax.net.ssl.HttpsURLConnection");

            HttpsURLConnection4.setDefaultSSLSocketFactory.implementation = function (factory) {
                logVerbose("HttpsURLConnection.setDefaultSSLSocketFactory 被调用，已拦截并替换");

                var TrustAllDefault = Java.use("javax.net.ssl.X509TrustManager");
                var EmptyTMDefault = Java.registerClass({
                    name: "com.sslunpin.HttpsDefaultTrustManager_" + _ts,
                    implements: [TrustAllDefault],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {},
                        getAcceptedIssuers: function () {
                            return [];
                        }
                    }
                });

                var sslCtxDefault = Java.use("javax.net.ssl.SSLContext").getInstance("TLS");
                var tmArrayDefault = Java.array("javax.net.ssl.TrustManager", [EmptyTMDefault.$new()]);
                sslCtxDefault.init(null, tmArrayDefault, null);

                this.setDefaultSSLSocketFactory(sslCtxDefault.getSocketFactory());
            };

            recordSuccess("HttpsURLConnection.setDefaultSSLSocketFactory");
        } catch (e) {
            recordFailure("HttpsURLConnection.setDefaultSSLSocketFactory", e);
        }
    }

    // ==================== 输出绕过结果汇总 ====================
    log("========================================");
    log("SSL Pinning 绕过安装完成");
    log("成功: " + successCount + " 个 | 失败: " + failCount + " 个");
    log("----------------------------------------");
    for (var r = 0; r < results.length; r++) {
        var item = results[r];
        var statusIcon = item.status === "SUCCESS" ? "[+]" : "[-]";
        var detail = item.status === "SUCCESS" ? "已安装" : "失败 (" + item.error + ")";
        log("  " + statusIcon + " " + item.name + " - " + detail);
    }
    log("========================================");
});
