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

## 此漏洞可能造成的后果

- 攻击者可通过结算接口构造折扣参数为 0 的请求实现 0 元购，服务直接开通
- 折扣参数可随查询串、表单或 JSON 请求体提交，WAF 等外层防护难以识别
- v1 接口和面板接口均可被利用，仅修复一个入口无法根治
- SQL注入可导致数据库信息泄露、用户密码被篡改、服务器被控制

## 补丁原理

补丁在 ThinkPHP 启动、进入路由解析前检查请求：

1. **拦截所有外部请求携带的折扣参数**（查询串、表单、JSON 请求体均覆盖）
2. **拦截SQL注入攻击**（检测特殊字符、SQL关键字、SQL函数等）
3. 命中即返回 HTTP 400，不再进入结算/升级逻辑
4. 默认不禁用 /v1 接口，正常结算、查询、登录等对接调用完全不受影响
5. 如需整体关闭 /v1 开放接口，将补丁内开关置为开启后生效（可选）

与 WAF 不同，本补丁运行在 PHP 应用进程内，检查的是框架实际解析到的请求数据，请求变形无法绕过。

## 特色功能

### 1. 全入口拦截

同时拦截 v1 接口和面板接口的 0 元购漏洞：

| 入口 | 路径 | 拦截 |
|------|------|------|
| v1 结算接口 | `/v1/cart/checkout` | ✅ |
| 面板结算接口 | `/cart/settle` | ✅ |
| 购物车结算 | `/cart?action=viewcart&statuscart=checkout` | ✅ |

### 2. 详细日志记录

自动记录攻击者信息，包括：
- 用户ID（从JWT token提取）
- 用户名
- 真实IP（X-Forwarded-For）
- 会话ID
- 完整请求参数

### 3. 随机嘲讽信息

当检测到攻击时，返回随机嘲讽信息，让攻击者知道被发现了：

```json
{
  "status": 400,
  "msg": "你0元购你妈逼呢，小乐子，被我拦下来了吧哈哈哈"
}
```

### 4. 可选关闭 v1 目录

如果不需要 v1 接口，可以一键关闭整个 `/v1` 目录。

## 注意事项

- 本补丁默认仅拦截折扣参数和SQL注入，不影响任何正常对接调用
- 折扣参数仅在服务端内部向资源方下单时由系统计算生成，客户端与对接方不应提交该参数
- 如需整体禁用 /v1 开放接口（如不再对外提供该接口），打开补丁内的路径拦截开关即可
- 这是一项紧急缓解措施。永久修复仍应在结算与升级逻辑中对折扣类参数做服务端计算与范围校验

## 安装方式

1. 将 `zjmf_0day_patch_pro.php` 放到魔方财务项目根目录

2. 在 `public/index.php` 中加载补丁。补丁应放在 ThinkPHP 基础文件之后：

```php
require CMF_ROOT . 'vendor/thinkphp/base.php';
require CMF_ROOT . 'zjmf_0day_patch_pro.php';   // <-- 添加此行
Container::get('app', [APP_PATH])->run()->send();
```

3. 如果已经安装其他启动补丁，保持各自的 `require` 行即可。

## 配置选项

在补丁文件顶部可以配置：

```php
// 是否关闭整个 /v1 目录（true=关闭，false=保留）
$disableV1 = false;
```

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

从 `public/index.php` 中删除对应的 `require` 行，然后删除项目根目录下的 `zjmf_0day_patch_pro.php` 和 `zjmf_security.log`。

## 作者

[锚点云](https://www.mdidc.net)

## 友链

- [帷云](https://www.vyidc.top)
- [锚点云](https://www.mdidc.net)

## 许可证

MIT
