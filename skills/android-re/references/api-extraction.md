# API 提取参考手册

本文档是 Android 逆向工程中 API 提取的详细参考指南。涵盖静态模式识别、动态抓取方法论、认证机制分析，以及静态与动态结果的关联策略。

---

## 1. Retrofit 注解模式识别

Retrofit 是 Android 应用中最常用的 HTTP 客户端框架。其 API 定义通过 Java 注解声明在接口方法上，是静态分析的首要目标。

### 1.1 HTTP 方法注解

jadx 搜索关键字：`@GET`、`@POST`、`@PUT`、`@DELETE`、`@PATCH`

```java
// 基本 GET 请求
@GET("api/v1/users")
Call<List<User>> getUsers();

// 带路径参数的 GET
@GET("api/v1/users/{id}")
Call<User> getUserById(@Path("id") long userId);

// POST 请求，带 JSON Body
@POST("api/v1/users")
Call<User> createUser(@Body UserRequest request);

// PUT 更新
@PUT("api/v1/users/{id}")
Call<User> updateUser(@Path("id") long id, @Body UserRequest request);

// DELETE 删除
@DELETE("api/v1/users/{id}")
Call<Void> deleteUser(@Path("id") long id);

// PATCH 局部更新
@PATCH("api/v1/users/{id}")
Call<User> patchUser(@Path("id") long id, @Body Map<String, Object> fields);
```

> **提示**：注解中的路径字符串即为相对 URL，结合 Base URL 可还原完整端点。

### 1.2 请求头注解

```java
// 静态请求头（编译时固定）
@Headers({
    "Accept: application/json",
    "X-Platform: android",
    "X-App-Version: 3.2.1"
})
@GET("api/v1/config")
Call<Config> getConfig();

// 动态请求头（运行时传入）
@GET("api/v1/profile")
Call<Profile> getProfile(@Header("Authorization") String token);

// HeaderMap 批量动态头
@GET("api/v1/data")
Call<Data> getData(@HeaderMap Map<String, String> headers);
```

jadx 搜索策略：搜索 `@Headers` 可发现静态头中隐藏的自定义字段（如 `X-Sign`、`X-Timestamp`），这些通常是签名校验的线索。

### 1.3 请求体注解

```java
// JSON Body（最常见，配合 GsonConverterFactory）
@POST("api/v1/login")
Call<LoginResponse> login(@Body LoginRequest body);

// 表单 Field（URL-encoded）
@FormUrlEncoded
@POST("api/v1/login")
Call<LoginResponse> login(
    @Field("username") String username,
    @Field("password") String password
);

// FieldMap（动态表单字段）
@FormUrlEncoded
@POST("api/v1/submit")
Call<Response> submit(@FieldMap Map<String, String> params);
```

> **注意**：`@Body` 需要追踪参数类型的类定义，从中提取 JSON 字段名。混淆后类名可能是 `a`、`b` 等，需结合 `@SerializedName` 注解或 Proguard mapping 还原。

### 1.4 查询参数注解

```java
// 单个查询参数
@GET("api/v1/search")
Call<SearchResult> search(@Query("keyword") String keyword);

// 多个查询参数
@GET("api/v1/list")
Call<ListResult> getList(
    @Query("page") int page,
    @Query("size") int size,
    @Query("sort") String sort
);

// QueryMap（动态参数集合）
@GET("api/v1/filter")
Call<FilterResult> filter(@QueryMap Map<String, String> options);

// QueryName（仅键名，无值）
@GET("api/v1/export")
Call<Export> export(@QueryName String format);
```

### 1.5 路径参数

```java
@GET("api/v1/orders/{orderId}/items/{itemId}")
Call<OrderItem> getOrderItem(
    @Path("orderId") String orderId,
    @Path("itemId") String itemId
);
```

路径参数在注解字符串中以 `{name}` 形式出现，方法签名中以 `@Path("name")` 绑定。

### 1.6 文件上传

```java
// 单文件上传
@Multipart
@POST("api/v1/upload")
Call<UploadResult> uploadFile(
    @Part MultipartBody.Part file,
    @Part("description") RequestBody description
);

// 多文件上传
@Multipart
@POST("api/v1/upload/batch")
Call<UploadResult> uploadFiles(
    @Part List<MultipartBody.Part> files,
    @PartMap Map<String, RequestBody> params
);
```

### 1.7 jadx 搜索策略

建议按以下优先级在 jadx 中搜索：

| 搜索词 | 目的 | 预期发现 |
|--------|------|----------|
| `@GET` / `@POST` | 定位 API 接口定义 | Retrofit 接口类 |
| `Retrofit.Builder` | 定位 Base URL | 服务器地址配置 |
| `baseUrl` | 备选 Base URL 搜索 | 可能在常量类中 |
| `@Headers` | 发现自定义请求头 | 签名字段、版本标识 |
| `@SerializedName` | 还原混淆字段名 | JSON 字段映射 |
| `addInterceptor` | 定位拦截器 | 认证逻辑、日志、重试 |

在混淆严重的情况下，接口注解中的字符串（URL 路径、头部名称）通常不会被混淆，因此仍然是可靠的搜索锚点。

---

## 2. OkHttp Builder 模式识别

OkHttp 是 Retrofit 的底层引擎。即使应用不使用 Retrofit，也几乎一定使用 OkHttp 或其变体。

### 2.1 OkHttpClient.Builder 配置链

jadx 搜索关键字：`OkHttpClient.Builder`、`new OkHttpClient`

```java
OkHttpClient client = new OkHttpClient.Builder()
    .connectTimeout(30, TimeUnit.SECONDS)
    .readTimeout(30, TimeUnit.SECONDS)
    .writeTimeout(30, TimeUnit.SECONDS)
    .addInterceptor(new AuthInterceptor())          // 应用层拦截器
    .addInterceptor(new LoggingInterceptor())
    .addNetworkInterceptor(new CacheInterceptor())  // 网络层拦截器
    .certificatePinner(certificatePinner)            // SSL Pinning
    .sslSocketFactory(sslSocketFactory, trustManager)
    .hostnameVerifier(hostnameVerifier)
    .build();
```

> **关键点**：`certificatePinner`、`sslSocketFactory`、`hostnameVerifier` 三者是 SSL Pinning 的实现位置，需要在动态分析中绕过。

### 2.2 Request.Builder 构建模式

jadx 搜索关键字：`Request.Builder`、`new Request`

```java
Request request = new Request.Builder()
    .url("https://api.example.com/v1/data")
    .addHeader("Authorization", "Bearer " + token)
    .addHeader("X-Timestamp", String.valueOf(System.currentTimeMillis()))
    .addHeader("X-Sign", generateSign(params))
    .post(RequestBody.create(MediaType.parse("application/json"), jsonBody))
    .build();
```

> **提示**：当应用不使用 Retrofit 而直接用 OkHttp 构建请求时，API 端点会以字符串形式出现在 `url()` 调用中。搜索 `Request.Builder` 可发现这类"裸"请求。

### 2.3 Interceptor 链

OkHttp 拦截器分为两类，理解其区别对逆向至关重要：

| 类型 | 注册方式 | 执行时机 | 典型用途 |
|------|----------|----------|----------|
| Application Interceptor | `addInterceptor()` | 最先执行，仅调用一次 | 添加认证头、签名、日志 |
| Network Interceptor | `addNetworkInterceptor()` | 在重定向后执行，每次网络调用 | 缓存控制、压缩 |

### 2.4 常见拦截器模式

**认证拦截器**（最重要，包含签名逻辑）：

```java
public class AuthInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request();
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
        String nonce = UUID.randomUUID().toString();
        String sign = SignUtil.generateSign(original.url().toString(), timestamp, nonce);

        Request signed = original.newBuilder()
            .addHeader("X-Timestamp", timestamp)
            .addHeader("X-Nonce", nonce)
            .addHeader("X-Signature", sign)
            .build();
        return chain.proceed(signed);
    }
}
```

**日志拦截器**：

```java
// HttpLoggingInterceptor（Square 官方）
HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
logging.setLevel(HttpLoggingInterceptor.Level.BODY);
builder.addInterceptor(logging);
```

> **逆向价值**：日志拦截器在 Release 版本中通常被设为 `Level.NONE`，但其存在说明开发阶段可能有调试日志残留。

**重试拦截器**：

```java
public class RetryInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        Response response = chain.proceed(request);
        int retryCount = 0;
        while (!response.isSuccessful() && retryCount < 3) {
            response.close();
            response = chain.proceed(request);
            retryCount++;
        }
        return response;
    }
}
```

**Token 刷新拦截器**：

```java
public class TokenRefreshInterceptor implements Interceptor {
    @Override
    public Response intercept(Chain chain) throws IOException {
        Response response = chain.proceed(chain.request());
        if (response.code() == 401) {
            String newToken = refreshToken();  // 关键：刷新逻辑
            Request retryRequest = chain.request().newBuilder()
                .header("Authorization", "Bearer " + newToken)
                .build();
            response.close();
            return chain.proceed(retryRequest);
        }
        return response;
    }
}
```

---

## 3. 认证模式识别

### 3.1 Bearer Token（JWT）

jadx 搜索关键字：`Bearer`、`Authorization`、`JWT`、`eyJ`

```java
// 典型模式
.addHeader("Authorization", "Bearer " + tokenManager.getAccessToken())
```

JWT 的结构为 `header.payload.signature`（Base64 编码），在抓包数据中以 `eyJ` 开头可快速识别。

**逆向要点**：
- 定位 Token 存储位置：SharedPreferences、SQLite、文件
- 追踪 Token 获取流程：登录接口 → Token 存储 → 后续请求携带
- 分析 Token 刷新机制：过期检测 → Refresh Token → 新 Access Token

### 3.2 API Key

```java
// Header 方式
.addHeader("X-API-Key", BuildConfig.API_KEY)

// Query 参数方式
@GET("api/v1/data")
Call<Data> getData(@Query("api_key") String apiKey);

// Cookie 方式
.addHeader("Cookie", "api_key=" + key)
```

jadx 搜索策略：搜索 `API_KEY`、`api_key`、`apiKey`、`appKey`、`app_secret`。API Key 通常存储在 `BuildConfig` 类、`strings.xml` 资源文件或 Native SO 库中。

### 3.3 HMAC 签名

国内 APP 最常见的认证方式，通常包含以下要素：

```
签名 = HMAC-SHA256(secret, 拼接串)
拼接串 = method + url + timestamp + nonce + sorted_params
```

jadx 搜索关键字：`HmacSHA256`、`HmacSHA1`、`HmacMD5`、`Mac.getInstance`、`SecretKeySpec`

```java
public static String generateSign(String method, String url,
        Map<String, String> params, String timestamp, String nonce) {
    // 1. 参数按 key 排序
    TreeMap<String, String> sorted = new TreeMap<>(params);
    // 2. 拼接参数字符串
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> entry : sorted.entrySet()) {
        sb.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
    }
    // 3. 构造待签名字符串
    String signStr = method + "\n" + url + "\n" + timestamp + "\n" + nonce + "\n" + sb.toString();
    // 4. HMAC 计算
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(SECRET.getBytes(), "HmacSHA256"));
    byte[] hash = mac.doFinal(signStr.getBytes("UTF-8"));
    // 5. 编码输出
    return Base64.encodeToString(hash, Base64.NO_WRAP);
}
```

> **逆向关键**：还原签名算法需要确定以下要素：
> 1. 哪些字段参与签名（method? url? params? body?）
> 2. 字段拼接顺序和分隔符（`\n`? `&`? 无分隔?）
> 3. 参数是否排序（通常按 key 字典序）
> 4. Secret Key 的来源（硬编码? 服务端下发? Native 层?）
> 5. 输出编码方式（Base64? Hex? 小写/大写?）

### 3.4 OAuth 2.0 流程

jadx 搜索关键字：`oauth`、`client_id`、`client_secret`、`grant_type`、`access_token`、`refresh_token`

```
Authorization Code 流程：
1. 打开授权页 → GET /oauth/authorize?client_id=xxx&redirect_uri=xxx&response_type=code
2. 用户授权后回调 → redirect_uri?code=AUTH_CODE
3. 换取 Token → POST /oauth/token (grant_type=authorization_code&code=AUTH_CODE)
4. 刷新 Token → POST /oauth/token (grant_type=refresh_token&refresh_token=xxx)
```

**逆向要点**：关注 `client_id` 和 `client_secret` 的存储位置，这两个值通常是硬编码的。

### 3.5 自定义签名算法（国内 APP 常见）

国内 APP 往往使用非标准的签名方案，常见特征：

| 特征 | 说明 |
|------|------|
| 请求头包含 `X-Sign` / `sign` / `signature` | 签名结果字段 |
| 请求头包含 `X-Timestamp` / `ts` | 时间戳防重放 |
| 请求头包含 `X-Nonce` / `nonce` | 随机数防重放 |
| 签名算法在 Native SO 中实现 | 增加逆向难度 |
| 使用自定义哈希或变种 MD5/SHA | 非标准算法 |

jadx 搜索策略（按优先级）：

1. 搜索 `sign` / `signature` → 定位签名生成方法
2. 搜索 `native` → 检查是否有 JNI 调用（SO 层实现）
3. 搜索 `System.loadLibrary` → 定位 SO 文件名
4. 在 Interceptor 中追踪 → 签名逻辑通常在拦截器中统一处理

如果签名算法在 SO 中实现，需要配合 IDA Pro 或 Ghidra 分析 Native 代码，或使用 Frida Hook Native 函数直接调用。

---

## 4. 动态抓取方法论

### 4.1 trace-api.js 使用指南

`trace-api.js` 是项目内置的 HTTP 请求追踪脚本，用于运行时捕获所有网络请求。

**基本用法**：

```bash
# 通过 frida-mcp spawn 模式启动
frida-mcp spawn <package-name>
# 注入脚本
frida-mcp load_script scripts/frida-scripts/trace-api.js
```

**输出格式**（JSON）：

```json
{
  "type": "http_request",
  "method": "POST",
  "url": "https://api.example.com/v1/login",
  "headers": {
    "Authorization": "Bearer eyJ...",
    "Content-Type": "application/json",
    "X-Sign": "a1b2c3d4..."
  },
  "body": "{\"username\":\"test\",\"password\":\"***\"}",
  "timestamp": 1700000000
}
```

**过滤配置**：

```javascript
// 白名单：仅追踪包含关键字的 URL
const URL_WHITELIST = ["api.example.com", "/v1/", "/v2/"];

// 黑名单：排除干扰 URL
const URL_BLACKLIST = ["google", "firebase", "analytics", "crashlytics"];
```

> **最佳实践**：先不设过滤运行一次，了解应用的全部网络请求；再根据结果配置白名单，减少噪音。

### 4.2 SSL Pinning 绕过后的抓包流程

完整流程：

```
1. 准备工作
   ├── 确认设备已 root / 使用 Magisk
   ├── 安装 Frida Server（版本需与 PC 端 frida-tools 匹配）
   └── 配置代理工具（Charles / mitmproxy / Burp Suite）

2. 注入 SSL 绕过
   ├── frida-mcp spawn <package>
   ├── 注入 ssl-unpin.js
   └── 确认日志输出 "SSL Pinning bypassed"

3. 配置设备代理
   ├── WiFi 设置中配置 HTTP 代理指向 PC
   ├── 安装代理工具的 CA 证书
   └── Android 7+ 需将证书安装为系统级（需 root）

4. 开始抓包
   ├── 同时注入 trace-api.js（双重保障）
   ├── 系统性操作应用各功能
   └── 记录每个操作对应的请求
```

### 4.3 功能覆盖策略

为确保触发应用的所有 API，需系统性地覆盖各功能模块：

**覆盖清单**：

```
用户模块
├── 注册（手机号/邮箱/第三方）
├── 登录（密码/验证码/生物识别）
├── 退出登录
├── 个人信息查看/编辑
├── 修改密码
└── Token 刷新（等待过期或手动触发）

核心业务模块
├── 首页加载（通常包含多个聚合 API）
├── 列表页（翻页、筛选、排序）
├── 详情页
├── 搜索（关键字、联想、历史）
├── 收藏/点赞/评论
└── 下单/支付流程

系统模块
├── 启动时的配置拉取（App Config）
├── 版本检查（Update Check）
├── 推送注册（Push Token）
├── 埋点上报（Analytics）
└── 错误上报（Crash Report）
```

> **技巧**：清除应用数据后重新启动，可以触发初始化流程中的全部 API（如引导页、协议同意、设备注册等）。

### 4.4 常见问题

**证书固定失败**：

| 症状 | 原因 | 解决方案 |
|------|------|----------|
| ssl-unpin.js 无输出 | 应用使用非标准 SSL 库 | 搜索自定义 TrustManager 实现，编写针对性 Hook |
| 请求超时 | 代理证书未被信任 | 检查系统证书安装，Android 7+ 需 Magisk 模块 |
| 部分请求失败 | 应用使用多种 Pinning 方式 | 同时绕过 OkHttp、HttpURLConnection、WebView |

**双向认证（mTLS）**：

```
特征：应用安装包中包含 .p12 / .pfx / .bks 证书文件
应对：
1. apktool decode 提取证书文件
2. jadx 搜索 KeyStore 加载逻辑，获取证书密码
3. 将客户端证书导入代理工具
4. 或使用 Frida Hook KeyStore 提取证书和密码
```

**请求重放检测**：

```
特征：相同请求第二次发送返回 403 或错误码
原因：服务端校验 timestamp + nonce 唯一性
应对：
1. 确保每次请求使用新的 timestamp 和 nonce
2. 分析签名算法中是否包含这两个字段
3. Python 复现时动态生成这两个值
```

---

## 5. 静态+动态结果关联

### 5.1 匹配策略：URL Pattern 对齐

将静态发现的 API 声明与动态抓取的实际请求进行对齐匹配：

```
静态发现                              动态抓取
---------                            ---------
@GET("api/v1/users/{id}")     <-->   GET https://api.example.com/api/v1/users/12345
@POST("api/v1/orders")        <-->   POST https://api.example.com/api/v1/orders
@GET("api/v1/search")         <-->   GET https://api.example.com/api/v1/search?q=test
```

**匹配规则**：
1. 将路径参数 `{id}` 替换为正则 `[^/]+` 进行模式匹配
2. 忽略 Query 参数部分，仅匹配路径
3. 比较 HTTP 方法（GET/POST/PUT/DELETE）
4. 确认 Base URL 一致性

### 5.2 补全策略：动态发现静态遗漏的 API

动态抓取可能发现静态分析遗漏的 API，常见原因：

| 遗漏原因 | 说明 | 示例 |
|----------|------|------|
| 动态 URL 拼接 | 不使用 Retrofit 注解，直接拼接字符串 | `url = BASE_URL + "/api/v1/" + module + "/" + action` |
| WebView 内请求 | H5 页面发起的 API 调用 | JavaScript Bridge 调用 |
| 第三方 SDK | 内嵌 SDK 的网络请求 | 支付、推送、统计 |
| 反射调用 | 通过反射调用网络方法 | `Method.invoke()` 触发请求 |
| 延迟加载 | 特定条件下才触发的 API | 定时任务、后台同步 |

**补全流程**：
1. 将动态发现但静态未匹配的 URL 列出
2. 在 jadx 中搜索 URL 路径片段，尝试定位代码位置
3. 如果在 Java 层找不到，检查 WebView 和 Native 层
4. 无法定位源码的 API 标记为"仅动态发现"，仍记录完整请求信息

### 5.3 参数验证：对比静态声明与动态实际值

```
验证维度        静态信息              动态验证
----------    ----------           ----------
URL Path      注解中的路径模板       实际请求 URL
HTTP Method   @GET/@POST 等        实际方法
Headers       @Headers/@Header     实际请求头（可能经过 Interceptor 补充）
Query Params  @Query/@QueryMap     实际 URL 参数
Request Body  @Body/@Field         实际请求体内容
Content-Type  隐含在注解类型中       实际 Content-Type 头
Auth Token    Interceptor 添加     实际 Authorization 头值
```

**重点差异排查**：
- 静态声明的 Header 与动态实际的 Header 差异 → Interceptor 动态添加的字段
- 静态参数类型与动态实际值格式差异 → 序列化/编码转换
- 静态未声明但动态出现的参数 → 通常由 Interceptor 统一注入

### 5.4 输出标准：API 文档完整性检查清单

最终输出的 API 文档（`output/<app-name>-api.md`）应通过以下检查：

**基础信息 (必须)**：

- [ ] Base URL 已确认（可能有多个环境：生产/预发/测试）
- [ ] API 版本号已标注（v1/v2/无版本号）
- [ ] 全局认证方式已说明
- [ ] 公共请求头已列出

**每个端点 (必须)**：

- [ ] HTTP 方法（GET/POST/PUT/DELETE/PATCH）
- [ ] 完整 URL 路径（含路径参数说明）
- [ ] 请求头（特别是认证相关头）
- [ ] 请求参数（Query 参数，含类型和是否必填）
- [ ] 请求体（JSON Schema 或字段列表）
- [ ] 响应体示例（至少包含成功响应）
- [ ] 来源标记（静态发现 / 动态发现 / 两者皆有）

**认证与签名 (如适用)**：

- [ ] Token 获取方式（登录接口）
- [ ] Token 刷新机制（Refresh Token 接口）
- [ ] 签名算法描述（算法类型、参与字段、拼接规则）
- [ ] 签名验证示例（输入 → 输出对照）

**覆盖度评估**：

- [ ] 静态发现的 API 总数
- [ ] 动态发现的 API 总数
- [ ] 匹配成功的数量
- [ ] 仅静态发现（未在动态中触发）的数量及原因推测
- [ ] 仅动态发现（静态未定义）的数量及来源分析

---

## 附录：快速参考

### jadx 搜索速查表

```
# Retrofit 接口
@GET    @POST    @PUT    @DELETE    @PATCH

# Base URL
Retrofit.Builder    baseUrl    BASE_URL    API_URL

# 请求配置
@Headers    @Header    @Body    @Field    @Query    @Path    @Part

# OkHttp
OkHttpClient.Builder    Request.Builder    addInterceptor

# 认证
Authorization    Bearer    Token    api_key    API_KEY

# 签名
sign    signature    HmacSHA    SecretKeySpec    Mac.getInstance

# 加密（交叉参考 algorithm-restore.md）
Cipher    encrypt    decrypt    AES    RSA    MD5    SHA

# Native 调用
native    System.loadLibrary    JNI
```

### 常见 Base URL 存储位置

1. `BuildConfig.java` → `BuildConfig.BASE_URL` 或 `BuildConfig.API_HOST`
2. Retrofit.Builder 调用处 → `.baseUrl("https://...")`
3. `strings.xml` 资源文件 → `<string name="api_host">...</string>`
4. 常量类 → `public static final String BASE_URL = "..."`
5. Gradle 配置（反编译后在 BuildConfig 中体现）
6. 远程配置（首次启动从服务端拉取，存入 SharedPreferences）
