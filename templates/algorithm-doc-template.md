# 算法还原文档: {应用名称}

> 分析时间: {日期}
> 应用版本: {版本号}
> 包名: {包名}

## 概述

| 项目 | 值 |
|------|-----|
| 算法用途 | 请求签名 / 数据加密 / Token 生成 |
| 算法类型 | AES-CBC / HMAC-SHA256 / RSA / 自定义 |
| 实现层 | Java / Native (SO) |

---

## 算法 1: {算法名称/用途}

### 基本信息

| 项目 | 值 |
|------|-----|
| 算法 | AES/CBC/PKCS5Padding |
| 密钥长度 | 128/256 bit |
| 代码位置 | `com.example.crypto.CryptoUtils#encrypt` |
| 调用场景 | 登录请求体加密 |

### 参数

#### Key
| 项目 | 值 |
|------|-----|
| 来源 | 硬编码 / 服务端 / Native / 派生 |
| 值 (Hex) | `0123456789abcdef0123456789abcdef` |
| 值 (Base64) | `ASNFZ4mrze8BI0VniavN7w==` |
| 代码位置 | `com.example.crypto.KeyManager#getKey` |

#### IV
| 项目 | 值 |
|------|-----|
| 生成方式 | 固定 / 随机(附在密文前) / 派生 |
| 值 (Hex) | `fedcba9876543210fedcba9876543210` |

### 数据流

```
原始数据
  ↓ UTF-8 编码
字节数组
  ↓ PKCS5 填充
填充后数据
  ↓ AES-CBC 加密 (Key + IV)
密文字节
  ↓ Base64 编码
密文字符串
  ↓ URL 编码（如需）
最终传输值
```

### Frida 捕获样本

```json
{
  "operation": "Cipher.doFinal",
  "algorithm": "AES/CBC/PKCS5Padding",
  "mode": "ENCRYPT",
  "key": { "hex": "...", "base64": "..." },
  "iv": { "hex": "..." },
  "input": { "hex": "...", "length": 32 },
  "output": { "hex": "...", "length": 48 },
  "stackTrace": "..."
}
```

### Python 复现代码

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

key = bytes.fromhex('0123456789abcdef0123456789abcdef')
iv = bytes.fromhex('fedcba9876543210fedcba9876543210')

def encrypt(plaintext: str) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def decrypt(ciphertext_b64: str) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')
```

### 验证结果

| 测试项 | 输入 | 期望输出 | 实际输出 | 结果 |
|--------|------|---------|---------|------|
| 加密 | `test123` | `xxxxx` | `xxxxx` | PASS |
| 解密 | `xxxxx` | `test123` | `test123` | PASS |

---

## 算法 2: {下一个算法}
<!-- 重复上述格式 -->

---

## 加密调用链路图

```
用户操作 (登录/下单/搜索)
  ↓
业务层 (Activity/ViewModel)
  ↓ 调用
加密层 (CryptoUtils.encrypt)
  ↓ 使用
密钥管理 (KeyManager.getKey)
  ↓
网络层 (Retrofit/OkHttp)
  ↓ 发送
服务端
```

## 附注

- Hook 脚本: `scripts/frida-scripts/hook-crypto.js`
- 分析方法: jadx 静态定位 + Frida 动态捕获
- 已知限制:
