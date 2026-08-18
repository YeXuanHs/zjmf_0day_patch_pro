# 魔方财务 0day 漏洞修复补丁 Pro 版

本项目是针对魔方财务多个高危漏洞的综合修复补丁。

## 适用版本

适用于所有使用魔方财务（ZJMF）系统的版本，包括：
- 存在 `/v1` 接口的版本（openapi）
- 仅使用面板接口的版本（home）

本补丁基于魔方财务解码源码完成代码核对和设计。

## 修复的漏洞

| # | 漏洞 | 风险等级 | 入口 | 摘要 |
|---|------|---------|------|------|
| 1 | 0元购（v1接口） | 严重 | `/v1/cart/checkout` | 结算接口信任客户端传入的折扣参数，传 0 可将订单金额归零 |
| 2 | 0元购（面板接口） | 严重 | `/cart/settle`、`/cart?action=viewcart&statuscart=checkout` | 面板结算接口同样存在折扣参数信任问题 |
| 3 | SQL注入 | 严重 | `/v1/funds`、`/v1/login`、`/v1/affiliates` 等 | 账单接口、登录接口、推介计划等存在SQL注入漏洞 |
| 4 | 短信/邮件轰炸 | 高 | `/v1/code`、`*Send*` 等 | 验证码可被绕过，导致短信/邮件轰炸 |
| 5 | 密码修改绕过 | 高 | `/v1/password` | 未携带旧密码可修改他人密码 |
| 6 | 开放重定向 | 中 | `redirect_url` 参数 | 登录令牌可被回跳到第三方站点泄露 |
| 7 | 注册验证码绕过 | 中 | `/v1/register`、`/register` | 图形验证码可被绕过直接注册 |

## 此漏洞可能造成的后果

- 攻击者可通过结算接口构造折扣参数为 0 的请求实现 0 元购，服务直接开通
- 折扣参数可随查询串、表单或 JSON 请求体提交，WAF 等外层防护难以识别
- v1 接口和面板接口均可被利用，仅修复一个入口无法根治
- SQL注入可导致数据库信息泄露、用户密码被篡改、服务器被控制
- 短信/邮件轰炸可导致大量验证码发送，造成资费损失和用户体验问题
- 密码修改绕过可导致任意用户密码被修改

## 补丁原理

补丁在 ThinkPHP 启动、进入路由解析前检查请求：

1. **拦截所有外部请求携带的折扣参数**（查询串、表单、JSON 请求体均覆盖）
2. **拦截SQL注入攻击**（检测特殊字符、SQL关键字、SQL函数等）
3. **强制图形验证码校验**（发送短信/邮件时必须通过图形验证码）
4. **发送频率限制**（同一手机号/邮箱，60秒内最多N次）
5. **改密安全加固**（拦截未携带旧密码的请求）
6. **开放重定向防护**（redirect_url 仅允许站内域名）
7. **注册验证码强制**（系统开启图形验证码时，注册必须通过校验）
8. 命中即返回 HTTP 400，不再进入结算/升级逻辑

与 WAF 不同，本补丁运行在 PHP 应用进程内，检查的是框架实际解析到的请求数据，请求变形无法绕过。

## 特色功能

### 1. 全入口拦截

同时拦截 v1 接口和面板接口的 0 元购漏洞：

| 入口 | 路径 | 拦截 |
|------|------|------|
| v1 结算接口 | `/v1/cart/checkout` | ✅ |
| 面板结算接口 | `/cart/settle` | ✅ |
| 购物车结算 | `/cart?action=viewcart&statuscart=checkout` | ✅ |

### 2. 短信/邮件轰炸防护

当系统开启图形验证码（`is_captcha=1`）时：

- **强制图形验证码** — 发送短信/邮件前必须通过图形验证码校验
- **直接验证** — 绕过系统原生的 `captcha_check()` 函数（存在 hook 绕过漏洞）
- **发送频率限制** — 同一手机号/邮箱，60秒内最多发送N次（默认3次，可配置）

### 3. 注册验证码强制

系统开启图形验证码（`is_captcha=1`）时：

- 注册接口必须携带图形验证码参数
- 验证码缺失或错误直接拦截
- 防止绕过验证码注册

### 4. 改密安全加固

拦截未携带旧密码的密码修改请求，覆盖：
- `/v1/password`（openapi 接口）
- `/modify_password`（面板接口）
- `/password`（其他接口）

### 5. 开放重定向防护

登录令牌回跳 `redirect_url` 仅允许站内域名，防止：
- 登录令牌被回跳到第三方站点泄露
- `//evil.com` 协议相对绕过拦截

### 6. 上游信息隐藏

自动过滤响应中的上游敏感字段：
- `api_type`、`upstream_pid`、`upstream_price_value` 等
- 后台管理路径自动排除

### 7. 详细日志记录

自动记录攻击者信息，包括：
- 用户ID（从JWT token提取）
- 用户名
- 真实IP（X-Forwarded-For）
- 会话ID
- 完整请求参数

### 8. 随机嘲讽信息

当检测到攻击时，返回随机嘲讽信息，让攻击者知道被发现了：

```json
{
  "status": 400,
  "msg": "你0元购你妈逼呢，小乐子，被我拦下来了吧哈哈哈"
}
```

### 9. 可选关闭 v1 目录

如果不需要 v1 接口，可以一键关闭整个 `/v1` 目录。

## 配置选项

在补丁文件顶部可以配置：

```php
// ============================================================
// 配置区（按需修改）
// ============================================================

// 是否关闭整个 /v1 目录（true=关闭，false=保留）
$disableV1 = false;

// 是否启用上游信息隐藏（true=启用，false=关闭）
$enableUpstreamHide = true;

// 允许的站内域名（开放重定向防护白名单）
// 默认自动获取当前域名，无需手动配置
// 如需放行其他域名（如CDN），在数组中添加即可
$allowedDomains = [
    $_SERVER['HTTP_HOST'] ?? '',              // 自动获取当前域名（如 example.com）
    'www.' . ($_SERVER['HTTP_HOST'] ?? ''),   // 自动添加 www 前缀（如 www.example.com）
    // 'cdn.example.com',                     // 自定义CDN域名（按需添加）
    // 'static.example.com',                  // 自定义静态资源域名（按需添加）
];

// 短信/邮件发送频率限制（每60秒最多发送次数，0=不限制）
$smsRateLimit = 3;
```

### 配置说明

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `$disableV1` | `false` | 是否关闭整个 /v1 目录 |
| `$enableUpstreamHide` | `true` | 是否启用上游信息隐藏 |
| `$allowedDomains` | 当前域名 | 开放重定向防护白名单，自动获取当前域名 |
| `$smsRateLimit` | `3` | 每60秒最多发送验证码次数，0=不限制 |

### 白名单配置示例

**默认配置（推荐）：**
```php
$allowedDomains = [
    $_SERVER['HTTP_HOST'] ?? '',
    'www.' . ($_SERVER['HTTP_HOST'] ?? ''),
];
```
自动获取当前域名，无需手动修改。

**添加CDN域名：**
```php
$allowedDomains = [
    $_SERVER['HTTP_HOST'] ?? '',
    'www.' . ($_SERVER['HTTP_HOST'] ?? ''),
    'cdn.example.com',
    'static.example.com',
];
```

**多域名站点：**
```php
$allowedDomains = [
    $_SERVER['HTTP_HOST'] ?? '',
    'www.' . ($_SERVER['HTTP_HOST'] ?? ''),
    'example.com',
    'www.example.com',
    'example.net',
    'www.example.net',
];
```

**不限制（不推荐）：**
```php
$allowedDomains = [];  // 空数组 = 不检查域名
```

## 安装方式

1. 将 `zjmf_0day_patch_pro.php` 放到魔方财务项目根目录

2. 在 `public/index.php` 中加载补丁。补丁应放在 ThinkPHP 基础文件之后：

```php
require CMF_ROOT . 'vendor/thinkphp/base.php';
require CMF_ROOT . 'zjmf_0day_patch_pro.php';   // <-- 添加此行
Container::get('app', [APP_PATH])->run()->send();
```

3. 如果已经安装其他启动补丁，保持各自的 `require` 行即可。

## 日志记录

攻击日志保存在补丁同目录的 `zjmf_security.log` 文件中。

### 日志格式

```
============ [security][zero_cost] ============
时间: 2026-08-18 14:36:44
用户ID: 114514
用户名: 田所浩二
IP: 172.68.85.225
真实IP: 114.51.41.91
请求路径: /v1/cart/checkout
浏览器: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
会话ID: abc123def456ghi789
来源: https://www.example.com/clientarea
参数: {"resource_percent_value":0,"checkout":1}
```

### 日志类型

| 类型 | 说明 |
|------|------|
| `zero_cost` | 零元购攻击 |
| `sql_injection` | SQL注入攻击 |
| `sms_bomb` | 短信/邮件轰炸（验证码缺失） |
| `sms_bomb_wrong_captcha` | 短信/邮件轰炸（验证码错误） |
| `sms_rate_limit` | 短信/邮件频率超限 |
| `register_captcha_bypass` | 注册验证码绕过 |
| `register_captcha_wrong` | 注册验证码错误 |
| `password_bypass` | 密码修改绕过 |
| `open_redirect` | 开放重定向攻击 |

### 日志字段说明

| 字段 | 说明 |
|------|------|
| 时间 | 攻击发生时间 |
| 用户ID | 攻击者的用户ID（从JWT token提取） |
| 用户名 | 攻击者的用户名 |
| IP | CDN节点IP |
| 真实IP | 攻击者真实IP（X-Forwarded-For） |
| 请求路径 | 攻击的接口路径 |
| 浏览器 | User-Agent |
| 会话ID | PHP会话ID |
| 来源 | Referer |
| 参数 | 完整请求参数 |

## 卸载方式

从 `public/index.php` 中删除对应的 `require` 行，然后删除项目根目录下的：
- `zjmf_0day_patch_pro.php`
- `zjmf_security.log`
- `zjmf_sms_rate.json`（频率限制记录文件）

## 作者

[锚点云](https://www.mdidc.net)

## 友链

- [帷云](https://www.vyidc.top)
- [锚点云](https://www.mdidc.net)

## 许可证

MIT
