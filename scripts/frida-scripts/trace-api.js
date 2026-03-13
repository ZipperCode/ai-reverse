/**
 * trace-api.js - HTTP API 调用追踪脚本
 *
 * 用于拦截和记录 Android 应用中的 HTTP/HTTPS 网络请求。
 * 支持 OkHttp3、HttpURLConnection、WebView 和 Retrofit 的 Hook。
 *
 * 用法: frida -U -f <package> -l trace-api.js
 */

"use strict";

// ==================== 配置区 ====================
var config = {
    hookOkHttp: true,            // 是否 Hook OkHttp3
    hookHttpURLConnection: true, // 是否 Hook HttpURLConnection
    hookWebView: true,           // 是否 Hook WebView
    urlWhitelist: [],            // URL 白名单（为空则追踪所有请求）
    urlBlacklist: [],            // URL 黑名单（匹配到的 URL 将被跳过）
    maxBodyLength: 4096,         // 请求/响应体最大长度，超出部分截断
    captureResponse: true,       // 是否捕获响应体
    verbose: false               // 是否输出详细日志
};

// ==================== 辅助函数 ====================

/**
 * 根据白名单和黑名单判断是否需要追踪该 URL
 * @param {string} url - 请求的 URL
 * @returns {boolean} 是否追踪
 */
function shouldTrace(url) {
    if (!url) return false;

    // 如果白名单非空，URL 必须匹配白名单中的某个模式
    if (config.urlWhitelist.length > 0) {
        var whitelisted = false;
        for (var i = 0; i < config.urlWhitelist.length; i++) {
            if (url.indexOf(config.urlWhitelist[i]) !== -1) {
                whitelisted = true;
                break;
            }
        }
        if (!whitelisted) return false;
    }

    // 检查黑名单，匹配则跳过
    for (var j = 0; j < config.urlBlacklist.length; j++) {
        if (url.indexOf(config.urlBlacklist[j]) !== -1) {
            return false;
        }
    }

    return true;
}

/**
 * 截断过长的请求/响应体，并添加截断标记
 * @param {string} body - 原始内容
 * @param {number} maxLen - 最大长度
 * @returns {string} 截断后的内容
 */
function truncateBody(body, maxLen) {
    if (!body) return "";
    maxLen = maxLen || config.maxBodyLength;
    if (body.length <= maxLen) return body;
    return body.substring(0, maxLen) + "...[截断，原始长度: " + body.length + "]";
}

/**
 * 将 OkHttp3 的 Headers 对象转换为 JS 对象
 * @param {object} headers - OkHttp3 Headers 实例
 * @returns {object} 键值对形式的 headers
 */
function headersToObject(headers) {
    var result = {};
    if (!headers) return result;
    try {
        var size = headers.size();
        for (var i = 0; i < size; i++) {
            var name = headers.name(i);
            var value = headers.value(i);
            result[name] = value;
        }
    } catch (e) {
        if (config.verbose) {
            console.log("[API-Trace][警告] 解析 Headers 失败: " + e);
        }
    }
    return result;
}

/**
 * 获取当前 Java 调用栈
 * @returns {string} 格式化后的调用栈
 */
function getStackTrace() {
    try {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackElements = exception.getStackTrace();
        var traces = [];
        // 最多保留 15 层调用栈，避免输出过长
        var limit = Math.min(stackElements.length, 15);
        for (var i = 0; i < limit; i++) {
            traces.push("    at " + stackElements[i].toString());
        }
        if (stackElements.length > limit) {
            traces.push("    ... 省略 " + (stackElements.length - limit) + " 行");
        }
        return traces.join("\n");
    } catch (e) {
        return "无法获取调用栈: " + e;
    }
}

/**
 * 输出标准化的 JSON 日志
 * @param {object} data - API 调用数据
 */
function emitLog(data) {
    var record = {
        type: "api",
        timestamp: new Date().toISOString(),
        method: data.method || "UNKNOWN",
        url: data.url || "",
        headers: data.headers || {},
        requestBody: data.requestBody || "",
        statusCode: data.statusCode || 0,
        responseBody: data.responseBody || "",
        duration: data.duration || "0ms",
        stackTrace: data.stackTrace || "",
        source: data.source || "UNKNOWN"
    };
    // 截断请求体和响应体
    record.requestBody = truncateBody(record.requestBody, config.maxBodyLength);
    record.responseBody = truncateBody(record.responseBody, config.maxBodyLength);

    console.log("[API-Trace] " + JSON.stringify(record, null, 2));
}

/**
 * 安全读取 OkHttp3 RequestBody 的内容
 * @param {object} requestBody - OkHttp3 RequestBody 实例
 * @returns {string} 请求体字符串
 */
function readRequestBody(requestBody) {
    if (!requestBody) return "";
    try {
        var Buffer = Java.use("okio.Buffer");
        var buffer = Buffer.$new();
        requestBody.writeTo(buffer);
        return buffer.readUtf8();
    } catch (e) {
        if (config.verbose) {
            console.log("[API-Trace][警告] 读取 RequestBody 失败: " + e);
        }
        return "[读取失败]";
    }
}

/**
 * 安全读取 OkHttp3 ResponseBody 的内容（使用 peekBody 避免消耗流）
 * @param {object} response - OkHttp3 Response 实例
 * @returns {string} 响应体字符串
 */
function readResponseBody(response) {
    if (!response || !config.captureResponse) return "";
    try {
        // 使用 peekBody 来避免消耗原始响应流
        var peekBody = response.peekBody(Java.use("java.lang.Long")
            .parseLong(String(config.maxBodyLength + 1024)));
        return peekBody.string();
    } catch (e) {
        if (config.verbose) {
            console.log("[API-Trace][警告] 读取 ResponseBody 失败: " + e);
        }
        return "[读取失败]";
    }
}

// ==================== 主逻辑 ====================

Java.perform(function () {
    console.log("[API-Trace] ====================================");
    console.log("[API-Trace] HTTP API 追踪脚本已加载");
    console.log("[API-Trace] OkHttp3: " + config.hookOkHttp);
    console.log("[API-Trace] HttpURLConnection: " + config.hookHttpURLConnection);
    console.log("[API-Trace] WebView: " + config.hookWebView);
    console.log("[API-Trace] ====================================");

    // ==================== OkHttp3 Hook ====================
    if (config.hookOkHttp) {
        try {
            // --- Hook RealCall.execute()：拦截同步请求 ---
            // 兼容 OkHttp 3.x (okhttp3.RealCall) 和 4.x (okhttp3.internal.connection.RealCall)
            var RealCall;
            var realCallClassName;
            try {
                RealCall = Java.use("okhttp3.RealCall");
                realCallClassName = "okhttp3.RealCall";
            } catch (e) {
                try {
                    RealCall = Java.use("okhttp3.internal.connection.RealCall");
                    realCallClassName = "okhttp3.internal.connection.RealCall";
                    console.log("[API-Trace][OkHttp3] 使用 OkHttp 4.x 类路径: " + realCallClassName);
                } catch (e2) {
                    throw new Error("无法找到 RealCall 类（尝试了 okhttp3.RealCall 和 okhttp3.internal.connection.RealCall）: " + e2);
                }
            }

            RealCall.execute.implementation = function () {
                var startTime = Date.now();
                var request = this.request();
                var url = request.url().toString();

                if (!shouldTrace(url)) {
                    return this.execute();
                }

                if (config.verbose) {
                    console.log("[API-Trace][OkHttp3] 捕获同步请求: " + url);
                }

                var response = this.execute();
                var duration = Date.now() - startTime;

                emitLog({
                    method: request.method(),
                    url: url,
                    headers: headersToObject(request.headers()),
                    requestBody: readRequestBody(request.body()),
                    statusCode: response.code(),
                    responseBody: readResponseBody(response),
                    duration: duration + "ms",
                    stackTrace: getStackTrace(),
                    source: "OkHttp3"
                });

                return response;
            };
            console.log("[API-Trace][OkHttp3] 已 Hook RealCall.execute()");

            // --- Hook RealCall.enqueue()：拦截异步请求 ---
            RealCall.enqueue.implementation = function (callback) {
                var request = this.request();
                var url = request.url().toString();

                if (!shouldTrace(url)) {
                    return this.enqueue(callback);
                }

                if (config.verbose) {
                    console.log("[API-Trace][OkHttp3] 捕获异步请求: " + url);
                }

                // 记录请求阶段的信息
                var reqMethod = request.method();
                var reqHeaders = headersToObject(request.headers());
                var reqBody = readRequestBody(request.body());
                var reqStackTrace = getStackTrace();
                var startTime = Date.now();

                // 包装 Callback 以捕获响应
                var Callback = Java.use("okhttp3.Callback");
                var originalCallback = callback;

                var wrappedCallback = Java.registerClass({
                    name: "com.frida.trace.WrappedCallback_" + Date.now() + "_" + Math.floor(Math.random() * 10000),
                    implements: [Callback],
                    methods: {
                        onResponse: function (call, response) {
                            var duration = Date.now() - startTime;
                            emitLog({
                                method: reqMethod,
                                url: url,
                                headers: reqHeaders,
                                requestBody: reqBody,
                                statusCode: response.code(),
                                responseBody: readResponseBody(response),
                                duration: duration + "ms",
                                stackTrace: reqStackTrace,
                                source: "OkHttp3"
                            });
                            originalCallback.onResponse(call, response);
                        },
                        onFailure: function (call, e) {
                            var duration = Date.now() - startTime;
                            emitLog({
                                method: reqMethod,
                                url: url,
                                headers: reqHeaders,
                                requestBody: reqBody,
                                statusCode: -1,
                                responseBody: "[请求失败] " + e.getMessage(),
                                duration: duration + "ms",
                                stackTrace: reqStackTrace,
                                source: "OkHttp3"
                            });
                            originalCallback.onFailure(call, e);
                        }
                    }
                }).$new();

                return this.enqueue(wrappedCallback);
            };
            console.log("[API-Trace][OkHttp3] 已 Hook RealCall.enqueue()");

            // --- Hook Interceptor Chain：捕获经过签名/修改后的最终请求 ---
            // 注意: OkHttp 4.x 中 RealInterceptorChain 可能位于 okhttp3.internal.http.RealInterceptorChain
            // 或 okhttp3.internal.connection.RealInterceptorChain，此处做兼容处理
            try {
                var RealInterceptorChain;
                try {
                    RealInterceptorChain = Java.use("okhttp3.internal.http.RealInterceptorChain");
                } catch (e) {
                    RealInterceptorChain = Java.use("okhttp3.internal.connection.RealInterceptorChain");
                    console.log("[API-Trace][OkHttp3] 使用 OkHttp 4.x RealInterceptorChain 类路径");
                }
                RealInterceptorChain.proceed.overload("okhttp3.Request").implementation = function (request) {
                    var url = request.url().toString();
                    if (shouldTrace(url) && config.verbose) {
                        console.log("[API-Trace][OkHttp3][Interceptor] 拦截器链中的请求: " +
                            request.method() + " " + url);
                        var headers = headersToObject(request.headers());
                        console.log("[API-Trace][OkHttp3][Interceptor] 最终 Headers: " +
                            JSON.stringify(headers));
                    }
                    return this.proceed(request);
                };
                console.log("[API-Trace][OkHttp3] 已 Hook RealInterceptorChain.proceed()");
            } catch (e) {
                console.log("[API-Trace][OkHttp3] RealInterceptorChain Hook 失败（可能版本不同）: " + e);
            }

            // --- Hook Request.Builder：追踪请求构建过程 ---
            try {
                var RequestBuilder = Java.use("okhttp3.Request$Builder");
                RequestBuilder.build.implementation = function () {
                    var request = this.build();
                    if (config.verbose) {
                        var url = request.url().toString();
                        if (shouldTrace(url)) {
                            console.log("[API-Trace][OkHttp3][Builder] 构建请求: " +
                                request.method() + " " + url);
                        }
                    }
                    return request;
                };
                console.log("[API-Trace][OkHttp3] 已 Hook Request.Builder.build()");
            } catch (e) {
                console.log("[API-Trace][OkHttp3] Request.Builder Hook 失败: " + e);
            }

        } catch (e) {
            console.log("[API-Trace][OkHttp3] Hook 失败（应用可能未使用 OkHttp3）: " + e);
        }
    }

    // ==================== HttpURLConnection Hook ====================
    if (config.hookHttpURLConnection) {
        try {
            var URL = Java.use("java.net.URL");
            // 用于存储每个连接对象关联的元数据
            var connectionMeta = {};
            var metaIdCounter = 0;

            // 定时清理过期的连接元数据（防止内存泄漏）
            var META_TIMEOUT_MS = 60000; // 60 秒超时
            setInterval(function () {
                var now = Date.now();
                var cleaned = 0;
                for (var key in connectionMeta) {
                    if (connectionMeta.hasOwnProperty(key) && connectionMeta[key].startTime) {
                        if (now - connectionMeta[key].startTime > META_TIMEOUT_MS) {
                            delete connectionMeta[key];
                            cleaned++;
                        }
                    }
                }
                if (cleaned > 0 && config.verbose) {
                    console.log("[API-Trace] 已清理 " + cleaned + " 条过期连接元数据");
                }
            }, 30000); // 每 30 秒检查一次

            // --- Hook URL.openConnection()：捕获连接创建和 URL ---
            URL.openConnection.overload().implementation = function () {
                var urlStr = this.toString();
                var conn = this.openConnection();

                if (shouldTrace(urlStr)) {
                    // 将元数据绑定到连接对象（通过 hashCode 标识）
                    var metaId = "conn_" + (metaIdCounter++);
                    try {
                        var hashCode = conn.hashCode();
                        connectionMeta[hashCode] = {
                            metaId: metaId,
                            url: urlStr,
                            startTime: Date.now(),
                            requestBody: "",
                            stackTrace: getStackTrace()
                        };
                    } catch (e) { /* 忽略 */ }

                    if (config.verbose) {
                        console.log("[API-Trace][HttpURLConnection] openConnection: " + urlStr);
                    }
                }
                return conn;
            };
            console.log("[API-Trace][HttpURLConnection] 已 Hook URL.openConnection()");

            // --- Hook getOutputStream()：捕获请求体 ---
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            var OutputStreamClass = Java.use("java.io.OutputStream");

            try {
                // Hook 通用的 HttpURLConnection.getOutputStream
                var implClasses = [
                    "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
                    "com.android.okhttp.internal.huc.HttpsURLConnectionImpl",
                    "java.net.HttpURLConnection"
                ];

                implClasses.forEach(function (className) {
                    try {
                        var Clazz = Java.use(className);
                        if (Clazz.getOutputStream) {
                            Clazz.getOutputStream.implementation = function () {
                                var stream = this.getOutputStream();
                                var hashCode = this.hashCode();
                                if (connectionMeta[hashCode] && config.verbose) {
                                    console.log("[API-Trace][HttpURLConnection] getOutputStream: " +
                                        connectionMeta[hashCode].url);
                                }
                                return stream;
                            };
                            console.log("[API-Trace][HttpURLConnection] 已 Hook " + className + ".getOutputStream()");
                        }
                    } catch (e) { /* 该实现类不存在，跳过 */ }
                });
            } catch (e) {
                console.log("[API-Trace][HttpURLConnection] getOutputStream Hook 失败: " + e);
            }

            // --- Hook getInputStream() / getResponseCode()：捕获响应 ---
            try {
                var responseClasses = [
                    "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
                    "com.android.okhttp.internal.huc.HttpsURLConnectionImpl"
                ];

                responseClasses.forEach(function (className) {
                    try {
                        var Clazz = Java.use(className);

                        // Hook getResponseCode
                        if (Clazz.getResponseCode) {
                            Clazz.getResponseCode.implementation = function () {
                                var code = this.getResponseCode();
                                var hashCode = this.hashCode();
                                var meta = connectionMeta[hashCode];

                                if (meta) {
                                    var duration = Date.now() - meta.startTime;
                                    var method = "GET";
                                    try { method = this.getRequestMethod(); } catch (e) { /* 忽略 */ }

                                    var respHeaders = {};
                                    try {
                                        var headerFields = this.getHeaderFields();
                                        var keySet = headerFields.keySet();
                                        var iter = keySet.iterator();
                                        while (iter.hasNext()) {
                                            var key = iter.next();
                                            if (key !== null) {
                                                respHeaders[key] = headerFields.get(key).toString();
                                            }
                                        }
                                    } catch (e) { /* 忽略 */ }

                                    emitLog({
                                        method: method,
                                        url: meta.url,
                                        headers: respHeaders,
                                        requestBody: meta.requestBody,
                                        statusCode: code,
                                        responseBody: config.captureResponse ? "[通过 getInputStream 获取]" : "",
                                        duration: duration + "ms",
                                        stackTrace: meta.stackTrace,
                                        source: "HttpURLConnection"
                                    });

                                    // 清理元数据防止内存泄漏
                                    delete connectionMeta[hashCode];
                                }
                                return code;
                            };
                            console.log("[API-Trace][HttpURLConnection] 已 Hook " + className + ".getResponseCode()");
                        }

                        // Hook getInputStream
                        if (Clazz.getInputStream) {
                            Clazz.getInputStream.implementation = function () {
                                var hashCode = this.hashCode();
                                var meta = connectionMeta[hashCode];

                                if (meta && config.verbose) {
                                    console.log("[API-Trace][HttpURLConnection] getInputStream: " + meta.url);
                                }
                                return this.getInputStream();
                            };
                            console.log("[API-Trace][HttpURLConnection] 已 Hook " + className + ".getInputStream()");
                        }
                    } catch (e) { /* 该实现类不存在，跳过 */ }
                });
            } catch (e) {
                console.log("[API-Trace][HttpURLConnection] 响应 Hook 失败: " + e);
            }

        } catch (e) {
            console.log("[API-Trace][HttpURLConnection] Hook 失败: " + e);
        }
    }

    // ==================== WebView Hook ====================
    if (config.hookWebView) {
        try {
            var WebView = Java.use("android.webkit.WebView");

            // --- Hook loadUrl(String)：捕获 WebView 页面加载请求 ---
            WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
                if (shouldTrace(url)) {
                    emitLog({
                        method: "GET",
                        url: url,
                        headers: {},
                        requestBody: "",
                        statusCode: 0,
                        responseBody: "",
                        duration: "0ms",
                        stackTrace: getStackTrace(),
                        source: "WebView"
                    });
                }
                return this.loadUrl(url);
            };
            console.log("[API-Trace][WebView] 已 Hook WebView.loadUrl(String)");

            // --- Hook loadUrl(String, Map)：捕获带自定义 Header 的 WebView 请求 ---
            WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, additionalHeaders) {
                if (shouldTrace(url)) {
                    var headers = {};
                    if (additionalHeaders) {
                        try {
                            var keySet = additionalHeaders.keySet();
                            var iter = keySet.iterator();
                            while (iter.hasNext()) {
                                var key = iter.next();
                                headers[key] = additionalHeaders.get(key);
                            }
                        } catch (e) { /* 忽略 */ }
                    }

                    emitLog({
                        method: "GET",
                        url: url,
                        headers: headers,
                        requestBody: "",
                        statusCode: 0,
                        responseBody: "",
                        duration: "0ms",
                        stackTrace: getStackTrace(),
                        source: "WebView"
                    });
                }
                return this.loadUrl(url, additionalHeaders);
            };
            console.log("[API-Trace][WebView] 已 Hook WebView.loadUrl(String, Map)");

            // --- Hook postUrl()：捕获 WebView POST 请求 ---
            WebView.postUrl.implementation = function (url, postData) {
                if (shouldTrace(url)) {
                    var body = "";
                    if (postData) {
                        try {
                            body = Java.use("java.lang.String").$new(postData, "UTF-8");
                        } catch (e) { body = "[二进制数据，长度: " + postData.length + "]"; }
                    }

                    emitLog({
                        method: "POST",
                        url: url,
                        headers: {},
                        requestBody: body,
                        statusCode: 0,
                        responseBody: "",
                        duration: "0ms",
                        stackTrace: getStackTrace(),
                        source: "WebView"
                    });
                }
                return this.postUrl(url, postData);
            };
            console.log("[API-Trace][WebView] 已 Hook WebView.postUrl()");

        } catch (e) {
            console.log("[API-Trace][WebView] Hook 失败: " + e);
        }
    }

    // ==================== Retrofit 注解检测 ====================
    // 运行时扫描已加载的类，检测是否使用了 Retrofit 并尝试 Hook
    try {
        var retrofitAnnotations = [
            "retrofit2.http.GET",
            "retrofit2.http.POST",
            "retrofit2.http.PUT",
            "retrofit2.http.DELETE",
            "retrofit2.http.PATCH",
            "retrofit2.http.HEAD",
            "retrofit2.http.OPTIONS"
        ];

        var hasRetrofit = false;
        try {
            Java.use("retrofit2.Retrofit");
            hasRetrofit = true;
        } catch (e) { /* Retrofit 未被使用 */ }

        if (hasRetrofit) {
            console.log("[API-Trace][Retrofit] 检测到 Retrofit，尝试 Hook 服务接口方法...");

            // Hook Retrofit.create() 来发现服务接口
            var Retrofit = Java.use("retrofit2.Retrofit");
            Retrofit.create.implementation = function (service) {
                console.log("[API-Trace][Retrofit] Retrofit.create() 被调用，服务接口: " +
                    service.getName());

                // 扫描接口方法上的注解
                var methods = service.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    var annotations = method.getAnnotations();
                    for (var j = 0; j < annotations.length; j++) {
                        var ann = annotations[j];
                        var annType = ann.annotationType().getName();
                        // 检查是否为 Retrofit HTTP 注解
                        for (var k = 0; k < retrofitAnnotations.length; k++) {
                            if (annType === retrofitAnnotations[k]) {
                                var httpMethod = annType.split(".").pop();
                                var annValue = "";
                                try { annValue = ann.value(); } catch (e) { /* 忽略 */ }
                                console.log("[API-Trace][Retrofit]   发现 @" + httpMethod +
                                    "(\"" + annValue + "\") -> " + method.getName());
                            }
                        }
                    }
                }

                return this.create(service);
            };
            console.log("[API-Trace][Retrofit] 已 Hook Retrofit.create()");

            // Hook ServiceMethod 的 invoke 以追踪实际调用
            try {
                var HttpServiceMethod = Java.use("retrofit2.HttpServiceMethod");
                HttpServiceMethod.invoke.implementation = function (args) {
                    if (config.verbose) {
                        console.log("[API-Trace][Retrofit] ServiceMethod.invoke() 被调用");
                    }
                    return this.invoke(args);
                };
                console.log("[API-Trace][Retrofit] 已 Hook HttpServiceMethod.invoke()");
            } catch (e) {
                if (config.verbose) {
                    console.log("[API-Trace][Retrofit] HttpServiceMethod Hook 失败: " + e);
                }
            }
        } else {
            console.log("[API-Trace][Retrofit] 未检测到 Retrofit，跳过相关 Hook");
        }
    } catch (e) {
        console.log("[API-Trace][Retrofit] 检测/Hook 失败: " + e);
    }

    console.log("[API-Trace] ====================================");
    console.log("[API-Trace] 所有 Hook 初始化完成，开始追踪...");
    console.log("[API-Trace] ====================================");
});
