# API 文档: {应用名称}

> 分析时间: {日期}
> 应用版本: {版本号}
> 包名: {包名}

## 基础信息

| 项目 | 值 |
|------|-----|
| Base URL | `https://api.example.com` |
| API 版本 | v1 |
| 数据格式 | JSON |
| 认证方式 | Bearer Token / API Key / HMAC 签名 |

## 认证机制

### 认证方式
<!-- 描述认证方式，如 Bearer Token、API Key、HMAC 签名等 -->

### Token 获取
<!-- 描述如何获取 Token -->

### 签名算法
<!-- 如果使用签名认证，描述签名算法 -->
```
签名规则:
签名字段:
签名示例:
```

---

## API 端点列表

### 1. {端点名称}

| 项目 | 值 |
|------|-----|
| 方法 | `GET` / `POST` / `PUT` / `DELETE` |
| 路径 | `/api/v1/resource` |
| 认证 | 是 / 否 |
| 来源 | 静态分析 / 动态抓取 / 两者 |

#### 请求头
| Header | 值 | 说明 |
|--------|-----|------|
| Authorization | `Bearer {token}` | 认证令牌 |
| Content-Type | `application/json` | 内容类型 |

#### 请求参数
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| param1 | string | 是 | 描述 |
| param2 | int | 否 | 描述 |

#### 请求体
```json
{
  "field1": "value1",
  "field2": 123
}
```

#### 响应
```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

#### 代码位置
- 接口定义: `com.example.api.ApiService#method`
- 调用位置: `com.example.ui.Activity#onAction`

---

### 2. {下一个端点}
<!-- 重复上述格式 -->

---

## 公共参数

| 参数 | 位置 | 说明 |
|------|------|------|
| timestamp | Header/Query | 请求时间戳 |
| sign | Header/Query | 请求签名 |
| device_id | Header | 设备标识 |
| version | Header | 应用版本 |

## 错误码

| 错误码 | 含义 |
|--------|------|
| 0 | 成功 |
| 401 | 未授权 |
| 403 | 禁止访问 |

## 附注

- 分析方法: 静态(jadx) + 动态(frida trace-api.js)
- 已知限制:
