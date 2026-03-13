# 算法还原参考手册

本文档是 Android 逆向工程中算法还原环节的详细参考。涵盖常见加密模式识别、密钥/IV 来源分析、`hook-crypto.js` 数据解读，以及 Python 复现模板。

---

## 1. 常见加密模式

### 1.1 AES 对称加密

AES 是 Android 应用中最常见的对称加密算法，常见模式如下：

| 模式 | 算法字符串 | 特征 |
|------|-----------|------|
| CBC + PKCS5Padding | `AES/CBC/PKCS5Padding` | 需要 IV，密文长度是 16 的倍数 |
| ECB + PKCS5Padding | `AES/ECB/PKCS5Padding` | 无需 IV，相同明文产生相同密文（不安全） |
| GCM + NoPadding | `AES/GCM/NoPadding` | 需要 IV（通常 12 字节），密文末尾附带认证 tag（16 字节） |
| CTR + NoPadding | `AES/CTR/NoPadding` | 需要 IV，密文长度与明文相同 |

**jadx 反编译中的典型写法：**

```java
// AES-CBC（最常见）
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
byte[] encrypted = cipher.doFinal(plaintext);

// AES-ECB（无IV）
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
byte[] encrypted = cipher.doFinal(plaintext);

// AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
byte[] encrypted = cipher.doFinal(plaintext);
// 注意：GCM 模式的密文 = 实际密文 + 16字节认证tag
```

### 1.2 RSA 非对称加密

| 模式 | 算法字符串 | 典型用途 |
|------|-----------|---------|
| PKCS1 填充 | `RSA/ECB/PKCS1Padding` | 公钥加密短数据（如 AES 密钥） |
| OAEP 填充 | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` | 更安全的公钥加密 |
| 无填充 | `RSA/ECB/NoPadding` | 较少见，通常是自定义实现 |

**jadx 反编译中的典型写法：**

```java
// RSA 公钥加密
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(pubKeyStr, 0));
PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
byte[] encrypted = cipher.doFinal(data);

// RSA 私钥签名
Signature signature = Signature.getInstance("SHA256withRSA");
signature.initSign(privateKey);
signature.update(data);
byte[] signed = signature.sign();
```

### 1.3 HMAC 消息认证码

| 类型 | 算法字符串 | 输出长度 |
|------|-----------|---------|
| HMAC-SHA256 | `HmacSHA256` | 32 字节 |
| HMAC-SHA1 | `HmacSHA1` | 20 字节 |
| HMAC-MD5 | `HmacMD5` | 16 字节 |

**jadx 反编译中的典型写法：**

```java
Mac mac = Mac.getInstance("HmacSHA256");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
mac.init(keySpec);
byte[] hmacResult = mac.doFinal(data);
```

### 1.4 Hash 哈希摘要

| 类型 | 输出长度 | 十六进制长度 |
|------|---------|------------|
| MD5 | 16 字节 | 32 字符 |
| SHA-1 | 20 字节 | 40 字符 |
| SHA-256 | 32 字节 | 64 字符 |
| SHA-512 | 64 字节 | 128 字符 |

**jadx 反编译中的典型写法：**

```java
MessageDigest md = MessageDigest.getInstance("MD5");
md.update(data);
byte[] digest = md.digest();
// 或一步完成
byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
```

### 1.5 自定义异或加密

某些应用使用简单的异或操作进行加解密，通常出现在轻度保护场景中。

**jadx 反编译中的典型写法：**

```java
// 单字节异或
byte[] result = new byte[data.length];
for (int i = 0; i < data.length; i++) {
    result[i] = (byte) (data[i] ^ key[i % key.length]);
}

// 混淆后可能表现为位运算，注意 ^（异或）运算符
```

### 1.6 Base64 编码

| 类型 | 特征 | Java 调用 |
|------|------|----------|
| 标准 Base64 | 包含 `+` 和 `/`，末尾可能有 `=` | `Base64.encode(data, Base64.DEFAULT)` |
| URL 安全 | 用 `-` 和 `_` 替代 `+` 和 `/` | `Base64.encode(data, Base64.URL_SAFE)` |
| 无换行 | 不插入换行符 | `Base64.encode(data, Base64.NO_WRAP)` |
| 自定义字母表 | 替换标准字母表中的字符 | 自定义实现，需分析字母表映射 |

**识别要点：** Base64 不是加密，而是编码。在加密链路中通常作为最后一步，将二进制密文转为可传输的字符串。

---

## 2. Key 来源模式

### 2.1 硬编码

密钥直接写在 Java 代码中，是最容易提取的方式。

```java
// 字符串形式
private static final String KEY = "1234567890abcdef";
byte[] keyBytes = KEY.getBytes("UTF-8");

// 字节数组形式
private static final byte[] KEY = {0x01, 0x02, 0x03, ...};

// Base64 编码形式
byte[] keyBytes = Base64.decode("MTIzNDU2Nzg5MGFiY2RlZg==", 0);
```

**搜索方法：** 在 jadx 中搜索 `SecretKeySpec`，回溯其第一个参数的来源。

### 2.2 服务端下发

密钥从服务器获取，通常在登录或应用初始化时下发。

```java
// 典型模式：从登录响应中提取
JSONObject resp = login(username, password);
String encryptKey = resp.getString("encrypt_key");
// 存入 SharedPreferences 或内存
```

**分析方法：**
- 搜索 `SharedPreferences` 相关的 key 存取操作
- 使用 `hook-crypto.js` 捕获 `SecretKeySpec` 构造函数，比对多次启动时密钥是否变化
- Hook 网络请求，查找响应中是否包含密钥字段

### 2.3 Native 层获取

密钥通过 JNI 从 SO 库中获取，增加了提取难度。

```java
// Java 侧声明
public class SecurityUtil {
    static { System.loadLibrary("security"); }
    public static native byte[] getKey();
    public static native String getSecretKey(String param);
}

// 使用
byte[] key = SecurityUtil.getKey();
SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
```

**分析方法：**
- jadx 搜索 `native` 关键字和 `System.loadLibrary`
- Hook `SecretKeySpec` 构造函数可直接捕获到密钥值，无需分析 SO 代码
- 如需理解密钥生成逻辑，需结合 IDA/Ghidra 分析对应 SO

### 2.4 PBKDF2 密钥派生

从用户密码或设备信息派生出密钥。

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
SecretKey secretKey = factory.generateSecret(spec);
byte[] keyBytes = secretKey.getEncoded();
```

**关注参数：**
- `password`：派生源（密码、设备 ID 等）
- `salt`：盐值（可能硬编码或从服务器获取）
- `iterations`：迭代次数（如 65536）
- `keyLength`：密钥长度（如 256 位）

### 2.5 Android Keystore

使用系统密钥管理机制，密钥不可导出。

```java
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
keyStore.load(null);
SecretKey key = (SecretKey) keyStore.getKey("myAlias", null);
```

**特点：** Keystore 中的密钥无法直接通过 Hook `getEncoded()` 获取（返回 null）。需要 Hook `Cipher.doFinal` 捕获加密的输入输出，用于对比验证，但密钥本身无法导出复现。

### 2.6 组合方式

多种来源拼接或变换后使用。

```java
// 示例：设备ID + 硬编码盐 → MD5 → 取前16字节作为AES密钥
String deviceId = Settings.Secure.getString(resolver, Settings.Secure.ANDROID_ID);
String raw = deviceId + "hardcoded_salt_value";
byte[] md5 = MessageDigest.getInstance("MD5").digest(raw.getBytes());
SecretKeySpec keySpec = new SecretKeySpec(md5, "AES");
```

**分析方法：** 需要逐步追踪数据流，结合 `hook-crypto.js` 捕获最终传入 `SecretKeySpec` 的密钥值，再反推生成逻辑。

---

## 3. IV 生成模式

### 3.1 固定 IV（硬编码）

最简单的方式，IV 不会变化。

```java
// 字符串转字节
byte[] iv = "0102030405060708".getBytes();
// 或十六进制字节数组
byte[] iv = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
```

**识别方法：** 多次触发加密，如果 `hook-crypto.js` 捕获的 IV 始终相同，则为硬编码。

### 3.2 随机 IV

每次加密使用随机 IV，通常附在密文前面一起传输。

```java
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);
// 加密后拼接：iv + ciphertext
byte[] result = new byte[iv.length + encrypted.length];
System.arraycopy(iv, 0, result, 0, iv.length);
System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
```

**识别方法：**
- 每次 IV 不同
- 密文前 16 字节（CBC）或 12 字节（GCM）即为 IV
- 解密时需先拆分出 IV 再解密

### 3.3 基于数据派生

从某些数据（如请求参数、时间戳）派生 IV。

```java
// 取 MD5 的前 16 字节
byte[] md5 = MessageDigest.getInstance("MD5").digest(someData.getBytes());
byte[] iv = Arrays.copyOf(md5, 16);

// 或使用时间戳
long timestamp = System.currentTimeMillis() / 1000;
byte[] iv = String.format("%016d", timestamp).getBytes();
```

**识别方法：** IV 有规律地变化，且与某些可观测数据（时间、请求内容等）存在关联。

### 3.4 复用 Key 的一部分

密钥的前 N 字节直接作为 IV。

```java
byte[] key = "1234567890abcdef1234567890abcdef".getBytes(); // 32字节
byte[] iv = Arrays.copyOf(key, 16); // 前16字节做IV
```

**识别方法：** 比较 `hook-crypto.js` 捕获的 key 和 IV 的 hex 值，如果 IV 与 key 的前缀完全一致，即为此模式。

---

## 4. hook-crypto.js 数据分析方法

### 4.1 输出 JSON 字段解读

`hook-crypto.js` 输出的每条记录为一个 JSON 对象，核心字段如下：

```json
{
  "type": "crypto",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "operation": "Cipher.doFinal",
  "algorithm": "AES/CBC/PKCS5Padding",
  "mode": "ENCRYPT",
  "key": {
    "hex": "0123456789abcdef0123456789abcdef",
    "base64": "ASNFZ4mrze8BI0VniavN7w=="
  },
  "iv": {
    "hex": "fedcba9876543210fedcba9876543210"
  },
  "input": {
    "hex": "48656c6c6f20576f726c64",
    "length": 11
  },
  "output": {
    "hex": "a1b2c3d4e5f6...",
    "length": 16
  },
  "stackTrace": "    at com.example.crypto.AESUtil.encrypt(AESUtil.java:45)\n    at com.example.api.RequestSigner.sign(RequestSigner.java:78)\n    ..."
}
```

**各字段含义：**

| 字段 | 说明 |
|------|------|
| `type` | 固定为 `"crypto"`，用于过滤日志 |
| `timestamp` | 捕获时间（ISO 8601 格式） |
| `operation` | 操作类型：`Cipher.init` / `Cipher.doFinal` / `MessageDigest.digest` / `Mac.doFinal` / `Signature.sign` 等 |
| `algorithm` | 算法字符串，如 `AES/CBC/PKCS5Padding`、`HmacSHA256`、`SHA-256` |
| `mode` | 加密模式：`ENCRYPT` / `DECRYPT` / `WRAP` / `UNWRAP`（仅 Cipher） |
| `key.hex` | 密钥的十六进制表示 |
| `key.base64` | 密钥的 Base64 表示 |
| `iv.hex` | IV 的十六进制表示（仅 CBC/GCM/CTR 等模式） |
| `input.hex` | 输入数据（明文/待哈希数据）的十六进制 |
| `input.length` | 输入数据的字节长度 |
| `output.hex` | 输出数据（密文/哈希值）的十六进制 |
| `output.length` | 输出数据的字节长度 |
| `stackTrace` | Java 调用堆栈 |

### 4.2 通过调用栈关联源码位置

调用栈是关联静态分析和动态数据的关键桥梁。

**分析步骤：**

1. 在 `stackTrace` 中找到业务代码的类和方法（排除 `javax.crypto`、`java.security` 等系统类）
2. 在 jadx 中打开对应的类（如 `com.example.crypto.AESUtil`）
3. 定位到具体方法和行号（如 `encrypt` 方法第 45 行）
4. 沿调用栈向上追溯，理解该加密操作的业务上下文

**示例分析：**

```
stackTrace:
    at javax.crypto.Cipher.doFinal(...)           ← 系统类，忽略
    at com.example.crypto.AESUtil.encrypt(AESUtil.java:45)   ← 加密工具类
    at com.example.api.RequestSigner.sign(RequestSigner.java:78)  ← 请求签名
    at com.example.api.ApiClient.post(ApiClient.java:120)    ← API 调用入口
```

从上面的调用栈可知：`ApiClient.post` 调用了 `RequestSigner.sign` 进行请求签名，内部使用 `AESUtil.encrypt` 做 AES 加密。

### 4.3 多次捕获对比分析

通过多次触发同一功能，对比捕获的数据来判断各参数的性质。

| 对比维度 | 固定值（硬编码） | 变化值（动态生成） |
|---------|---------------|-----------------|
| key | 每次相同 | 每次不同（可能会话级别一致） |
| IV | 每次相同 | 每次不同 |
| input | 与请求参数对应 | 随输入变化 |
| output | 相同输入+相同key+相同IV → 相同输出 | 随 IV 或 key 变化 |

**操作建议：**

1. **同参数触发两次**：比较 key、IV 是否变化。不变则为硬编码，变化则需追踪来源
2. **不同参数触发两次**：观察 input 字段的变化规律，确认明文的序列化方式
3. **重启应用后再触发**：判断 key 是会话级（重启后变化）还是持久化的
4. **不同账号触发**：判断 key 是否与用户绑定

### 4.4 加密链路还原

许多应用采用多步加密，需要按顺序还原完整链路。

**通过 timestamp 排序确认执行顺序：**

```
10:30:45.100  MessageDigest.digest  (SHA-256)   → 对请求参数做哈希
10:30:45.102  SecretKeySpec.<init>  (AES)       → 构造AES密钥
10:30:45.103  IvParameterSpec.<init>            → 构造IV
10:30:45.103  Cipher.init           (ENCRYPT)   → 初始化加密器
10:30:45.104  Cipher.doFinal        (AES/CBC)   → 执行AES加密
10:30:45.105  Mac.doFinal           (HmacSHA256)→ 对密文做HMAC签名
```

**还原后的加密链路：**
```
原始参数 → SHA-256 哈希 → AES-CBC 加密 → HMAC-SHA256 签名
              ↓                ↓                ↓
          参数摘要          加密请求体        请求签名头
```

**关键技巧：**
- 一次操作中 `Cipher.doFinal` 的 `output` 如果出现在后续 `Mac.update` 的 `input` 中，说明存在加密链
- 比对各步骤 input/output 的 hex 值来确定数据流转关系
- 关注 `Cipher.update` 和 `Cipher.doFinal` 的配合（大数据分块加密场景）

---

## 5. Python 复现模板

以下模板基于 `pycryptodome` 库（`pip install pycryptodome`）。

### 5.1 AES-CBC 加解密

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC 加密，PKCS7 填充"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC 解密，去除 PKCS7 填充"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)

# 使用示例（key/iv 来自 hook-crypto.js 捕获的 hex 值）
key = bytes.fromhex("0123456789abcdef0123456789abcdef")  # 16字节=AES-128
iv  = bytes.fromhex("fedcba9876543210fedcba9876543210")   # 16字节

# 加密
plaintext = b"Hello World"
encrypted = aes_cbc_encrypt(plaintext, key, iv)
print("密文(hex):", encrypted.hex())
print("密文(base64):", base64.b64encode(encrypted).decode())

# 解密
decrypted = aes_cbc_decrypt(encrypted, key, iv)
print("明文:", decrypted.decode())

# 随机IV场景：密文前16字节是IV
def aes_cbc_decrypt_with_prepended_iv(data: bytes, key: bytes) -> bytes:
    """解密前16字节为IV的密文"""
    iv = data[:16]
    ciphertext = data[16:]
    return aes_cbc_decrypt(ciphertext, key, iv)
```

### 5.2 AES-GCM 加解密

```python
from Crypto.Cipher import AES
import base64

def aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes,
                    aad: bytes = None) -> tuple:
    """AES-GCM 加密，返回 (密文, tag)"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes,
                    tag: bytes, aad: bytes = None) -> bytes:
    """AES-GCM 解密并验证 tag"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# 使用示例
key   = bytes.fromhex("0123456789abcdef0123456789abcdef")  # 16字节
nonce = bytes.fromhex("aabbccddeeff00112233445566")         # 12字节（GCM推荐）

# 加密
plaintext = b"Hello World"
ciphertext, tag = aes_gcm_encrypt(plaintext, key, nonce)
print("密文(hex):", ciphertext.hex())
print("Tag(hex):", tag.hex())

# Java/Android 中密文通常是 ciphertext + tag 拼接
combined = ciphertext + tag
print("组合(hex):", combined.hex())

# 解密（拆分密文和tag）
def aes_gcm_decrypt_combined(combined: bytes, key: bytes, nonce: bytes) -> bytes:
    """解密 Java 风格的 GCM 密文（密文+tag拼接）"""
    ciphertext = combined[:-16]  # 最后16字节是tag
    tag = combined[-16:]
    return aes_gcm_decrypt(ciphertext, key, nonce, tag)
```

### 5.3 RSA 公钥加密 / 验签

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def rsa_encrypt_pkcs1(plaintext: bytes, pub_key_pem: str) -> bytes:
    """RSA PKCS1v1.5 公钥加密"""
    key = RSA.import_key(pub_key_pem)
    cipher = Cipher_PKCS1.new(key)
    return cipher.encrypt(plaintext)

def rsa_encrypt_oaep(plaintext: bytes, pub_key_pem: str) -> bytes:
    """RSA OAEP 公钥加密"""
    key = RSA.import_key(pub_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(plaintext)

def rsa_verify_sha256(data: bytes, signature: bytes, pub_key_pem: str) -> bool:
    """RSA SHA256withRSA 验签"""
    key = RSA.import_key(pub_key_pem)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# 使用示例
# 公钥通常从 jadx 反编译代码中提取（Base64 编码的 DER 格式）
pub_key_b64 = "MIIBIjANBgkqhk..."  # 从应用中提取
pub_key_der = base64.b64decode(pub_key_b64)
pub_key_pem = (
    b"-----BEGIN PUBLIC KEY-----\n"
    + base64.encodebytes(pub_key_der)
    + b"-----END PUBLIC KEY-----"
)

# 加密
encrypted = rsa_encrypt_pkcs1(b"secret data", pub_key_pem)
print("密文(base64):", base64.b64encode(encrypted).decode())

# 验签
is_valid = rsa_verify_sha256(b"signed data", signature_bytes, pub_key_pem)
print("签名验证:", "通过" if is_valid else "失败")
```

### 5.4 HMAC-SHA256 签名

```python
import hmac
import hashlib

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 签名"""
    return hmac.new(key, data, hashlib.sha256).digest()

def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 签名，返回十六进制字符串"""
    return hmac.new(key, data, hashlib.sha256).hexdigest()

# 使用示例（key 来自 hook-crypto.js 捕获的 Mac.init 中的 key.hex）
key  = bytes.fromhex("0123456789abcdef0123456789abcdef")
data = b"param1=value1&param2=value2&timestamp=1705286400"

result_hex = hmac_sha256_hex(key, data)
print("HMAC(hex):", result_hex)

# 与 hook-crypto.js 捕获的 Mac.doFinal output.hex 比对验证

# HMAC-SHA1 变体
def hmac_sha1_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha1).hexdigest()
```

### 5.5 MD5 / SHA256 哈希

```python
import hashlib

def md5_hex(data: bytes) -> str:
    """MD5 哈希，返回32位十六进制字符串"""
    return hashlib.md5(data).hexdigest()

def sha256_hex(data: bytes) -> str:
    """SHA-256 哈希，返回64位十六进制字符串"""
    return hashlib.sha256(data).hexdigest()

def sha1_hex(data: bytes) -> str:
    """SHA-1 哈希，返回40位十六进制字符串"""
    return hashlib.sha1(data).hexdigest()

def sha512_hex(data: bytes) -> str:
    """SHA-512 哈希，返回128位十六进制字符串"""
    return hashlib.sha512(data).hexdigest()

# 使用示例
data = b"Hello World"
print("MD5:   ", md5_hex(data))
print("SHA1:  ", sha1_hex(data))
print("SHA256:", sha256_hex(data))

# 与 hook-crypto.js 捕获的 MessageDigest.digest output.hex 比对验证

# 多步 update 场景（分段哈希）
def md5_multi_update(*parts: bytes) -> str:
    """模拟 Java 中多次 MessageDigest.update 后 digest 的场景"""
    m = hashlib.md5()
    for part in parts:
        m.update(part)
    return m.hexdigest()

# 示例：应用先 update("param1=value1&") 再 update("param2=value2")
result = md5_multi_update(b"param1=value1&", b"param2=value2")
print("分段MD5:", result)
```

---

## 6. Native 层加密处理

当加密逻辑位于 SO（共享库）中时，需要结合 Native 分析手段。

### 6.1 识别 JNI 方法

**jadx 中的特征标志：**

```java
// native 关键字标识 JNI 方法
public class NativeCrypto {
    // 加载 SO 库
    static {
        System.loadLibrary("crypto");     // 对应 libcrypto.so
        // 或
        System.load("/data/local/tmp/libcrypto.so");  // 绝对路径加载
    }

    // native 方法声明（无方法体）
    public static native byte[] encrypt(byte[] data, String key);
    public static native String sign(String params, long timestamp);
    private native byte[] nativeProcess(byte[] input, int mode);
}
```

**jadx 搜索关键字：**
- `native ` — 搜索 native 方法声明
- `System.loadLibrary` — 搜索 SO 加载
- `System.load` — 搜索绝对路径加载

### 6.2 Frida Hook Native 函数

**Hook JNI 导出函数：**

```javascript
// 方法一：通过 Module.findExportByName 直接 hook
var funcAddr = Module.findExportByName("libcrypto.so", "Java_com_example_NativeCrypto_encrypt");
if (funcAddr) {
    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            // args[0] = JNIEnv*, args[1] = jclass/jobject
            // args[2] 起为 Java 参数
            console.log("[Native] encrypt called");
            // 读取 byte[] 参数
            var env = Java.vm.getEnv();
            var arrayPtr = args[2];
            var length = env.getArrayLength(arrayPtr);
            var bytes = env.getByteArrayElements(arrayPtr, null);
            console.log("[Native] input length:", length);
            console.log("[Native] input hex:", hexdump(bytes, {length: length}));
        },
        onLeave: function(retval) {
            console.log("[Native] encrypt returned");
        }
    });
}
```

**Hook 任意 Native 函数（已知偏移地址）：**

```javascript
// 方法二：通过基址+偏移 hook（IDA/Ghidra 中获取偏移）
var base = Module.findBaseAddress("libcrypto.so");
var targetFunc = base.add(0x1A3C);  // IDA 中的函数偏移
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("[Native] func at 0x1A3C called");
        console.log("[Native] arg0:", args[0]);
        console.log("[Native] arg1:", args[1]);
        // 读取 C 字符串
        if (args[1].readPointer() != 0) {
            console.log("[Native] arg1 string:", args[1].readUtf8String());
        }
    },
    onLeave: function(retval) {
        console.log("[Native] return:", retval);
    }
});
```

### 6.3 常见 Native 加密库

| 库名 | 特征 SO 导出符号 | 说明 |
|------|----------------|------|
| OpenSSL | `EVP_EncryptInit_ex`, `EVP_DigestUpdate`, `AES_encrypt` | 最常见的开源加密库 |
| mbedTLS | `mbedtls_aes_crypt_cbc`, `mbedtls_md_hmac` | 轻量级 TLS 库 |
| BoringSSL | 与 OpenSSL 类似但有差异 | Google fork 的 OpenSSL |
| 自研加密 | 无标准符号，需 IDA 分析逻辑 | 手写实现，变化多端 |

**Frida 枚举 SO 导出符号：**

```javascript
// 列出目标 SO 的所有导出函数
var exports = Module.enumerateExports("libcrypto.so");
exports.forEach(function(exp) {
    if (exp.type === "function") {
        console.log(exp.name, exp.address);
    }
});

// 搜索包含关键字的导出
exports.filter(function(exp) {
    return exp.name.indexOf("AES") !== -1 || exp.name.indexOf("encrypt") !== -1;
}).forEach(function(exp) {
    console.log("[Crypto Export]", exp.name, exp.address);
});
```

### 6.4 IDA / Ghidra 辅助分析

**IDA 分析流程：**

1. 用 IDA 打开目标 SO 文件（注意选择正确架构：arm64-v8a / armeabi-v7a）
2. 搜索 JNI 注册函数：`JNI_OnLoad`（动态注册）或 `Java_` 前缀（静态注册）
3. 查找字符串引用：`"AES"`, `"RSA"`, 密钥常量等
4. 分析加密函数的参数传递和返回值
5. 结合 Frida Hook 验证 IDA 分析的结论

**Ghidra 分析流程：**

1. 新建项目，导入 SO 文件
2. 自动分析完成后查看函数列表
3. 使用 Decompiler 窗口查看伪 C 代码
4. 使用 `Search > For Strings` 查找加密相关字符串
5. 使用交叉引用（Xrefs）追踪数据流

**动态注册的 JNI 函数定位：**

```javascript
// Hook RegisterNatives 获取动态注册的 native 方法映射
var RegisterNatives = Module.findExportByName(null, "RegisterNatives");
// 更可靠的方式：Hook JNINativeInterface 的 RegisterNatives
var artModule = Process.findModuleByName("libart.so");
var symbols = artModule.enumerateSymbols();
symbols.forEach(function(sym) {
    if (sym.name.indexOf("RegisterNatives") !== -1 && sym.name.indexOf("Check") === -1) {
        Interceptor.attach(sym.address, {
            onEnter: function(args) {
                var className = Java.vm.getEnv().getStringUtfChars(
                    Java.vm.getEnv().callObjectMethod(args[1],
                    Java.vm.getEnv().getMethodId(
                        Java.vm.getEnv().findClass("java/lang/Class"),
                        "getName", "()Ljava/lang/String;")), null);
                console.log("[RegisterNatives] class:", className);
            }
        });
    }
});
```

### 6.5 Hook dlopen / dlsym 追踪 SO 加载

在某些场景下，SO 是动态加载的（如从网络下载或解密后加载）。

```javascript
// Hook dlopen 追踪 SO 加载
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        var path = args[0].readCString();
        console.log("[dlopen]", path);
        this.path = path;
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("crypto") !== -1) {
            console.log("[dlopen] 目标 SO 已加载:", this.path, "handle:", retval);
        }
    }
});

// Hook android_dlopen_ext（Android 7+ 实际使用的加载函数）
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {
        var path = args[0].readCString();
        console.log("[android_dlopen_ext]", path);
    }
});

// Hook dlsym 追踪符号解析
Interceptor.attach(Module.findExportByName(null, "dlsym"), {
    onEnter: function(args) {
        var symbol = args[1].readCString();
        console.log("[dlsym]", symbol);
    },
    onLeave: function(retval) {
        console.log("[dlsym] address:", retval);
    }
});
```

---

## 附录：快速排查清单

在还原一个加密算法时，按以下清单逐项确认：

- [ ] **算法类型**：AES / RSA / HMAC / Hash / 自定义？
- [ ] **算法参数**：模式（CBC/GCM/ECB）、填充（PKCS5/NoPadding）？
- [ ] **密钥来源**：硬编码 / 服务端下发 / Native / 派生 / Keystore？
- [ ] **密钥格式**：hex 字符串 / Base64 / UTF-8 字符串 / 原始字节？
- [ ] **密钥长度**：128位(16字节) / 192位(24字节) / 256位(32字节)？
- [ ] **IV 来源**：硬编码 / 随机（附在密文前） / 派生 / 复用Key？
- [ ] **IV 长度**：16字节（CBC/CTR） / 12字节（GCM）？
- [ ] **数据编码**：Base64 / Hex / URL编码？
- [ ] **加密链路**：是否存在多步加密？顺序是什么？
- [ ] **Python 复现**：输出是否与 hook-crypto.js 捕获的密文一致？
