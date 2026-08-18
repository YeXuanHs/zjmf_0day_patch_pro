<?php
/**
 * zjmf_0day_patch_pro（魔方财务漏洞修复补丁 Pro版）
 * 
 * 功能：
 * 1. 拦截零元购漏洞（resource_percent_value 等价格操控参数）
 * 2. 拦截SQL注入漏洞（keywords、account、search_desc 等）
 * 3. 可选关闭整个 /v1 目录
 * 
 * 加载方式：在 /public/index.php 的 require base.php 之后加一行：
 * require CMF_ROOT . 'zjmf_0day_patch_pro.php';
 */

// ============================================================
// 配置区（按需修改）
// ============================================================

// 是否关闭整个 /v1 目录（true=关闭，false=保留）
$disableV1 = false;

// ============================================================

if (PHP_SAPI === 'cli') {
    return;
}

// ---------- 功能1：关闭 /v1 目录（可选） ----------
if ($disableV1) {
    $mfcwPath = parse_url(
        (string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'),
        PHP_URL_PATH
    );

    if (!is_string($mfcwPath) || $mfcwPath === '') {
        $mfcwPath = '/';
    }

    for ($round = 0; $round < 3; $round++) {
        $decoded = rawurldecode($mfcwPath);
        if ($decoded === $mfcwPath) {
            break;
        }
        $mfcwPath = $decoded;
    }

    $mfcwPath = str_replace('\\', '/', $mfcwPath);
    $mfcwPath = preg_replace('#/+#', '/', $mfcwPath);
    $mfcwPath = preg_replace('#^/index\.php/#i', '/', $mfcwPath);
    $mfcwPath = rtrim($mfcwPath, '/');

    if (preg_match('#^/v1(?:/|$)#i', $mfcwPath) === 1) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(
            ['status' => 404, 'msg' => 'Not Found'],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );
        exit;
    }
}

// ---------- 获取请求信息 ----------
$mfcwMethod = strtoupper((string)(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET'));
$mfcwPath = parse_url(
    (string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'),
    PHP_URL_PATH
);

if (!is_string($mfcwPath) || $mfcwPath === '') {
    $mfcwPath = '/';
}

$mfcwPath = preg_replace('#^/index\.php#i', '', $mfcwPath);
$mfcwPath = '/' . trim($mfcwPath, '/');

$mfcwAction = isset($_GET['action']) ? $_GET['action'] : (isset($_POST['action']) ? $_POST['action'] : '');
$mfcwStatusCart = isset($_GET['statuscart']) ? $_GET['statuscart'] : (isset($_POST['statuscart']) ? $_POST['statuscart'] : '');

// 读取 JSON body
$mfcwJsonBody = null;
$mfcwRawBody = '';
if (strpos(strtolower((string)(isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '')), 'application/json') !== false) {
    $mfcwRawBody = file_get_contents('php://input');
    if (is_string($mfcwRawBody) && $mfcwRawBody !== '') {
        $mfcwJsonBody = json_decode($mfcwRawBody, true);
    }
}

// 合并所有参数
$mfcwAllParams = array_merge($_GET, $_POST, is_array($mfcwJsonBody) ? $mfcwJsonBody : []);

// ---------- 功能2：拦截零元购漏洞 ----------
$mfcwIsCheckout = (
    $mfcwPath === '/cart'
    && $mfcwAction === 'viewcart'
    && $mfcwStatusCart === 'checkout'
) || $mfcwPath === '/cart/settle'
  || $mfcwPath === '/v1/cart/checkout';

if ($mfcwIsCheckout && $mfcwMethod === 'POST') {
    $dangerousPriceParams = [
        'resource_percent_value',
        'resource_percent',
        'percent_value',
        'discount_percent',
        'price_percent',
        'custom_price',
        'override_price',
        'price_override',
        'amount_override',
    ];

    $mfcwBlocked = false;
    foreach ($dangerousPriceParams as $param) {
        if (array_key_exists($param, $mfcwAllParams)) {
            $mfcwBlocked = true;
            break;
        }
    }

    if ($mfcwBlocked) {
        logAttack('zero_cost', $mfcwAllParams);
        blockResponse();
    }
}

// ---------- 功能3：拦截SQL注入漏洞 ----------
$mfcwIsSqlVulnerable = (
    $mfcwPath === '/v1/funds'
    || $mfcwPath === '/v1/login'
    || $mfcwPath === '/v1/login_api'
    || $mfcwPath === '/login'
    || $mfcwPath === '/v1/affiliates'
    || $mfcwPath === '/v1/affiliates/record'
    || $mfcwPath === '/v1/affiliates/withdraw_record'
);

if ($mfcwIsSqlVulnerable) {
    $sqlInjectionPatterns = [
        "'", '"', ';', '--', '#', '/*', '*/',
        ' OR ', ' AND ', ' UNION ', ' SELECT ', ' INSERT ', 
        ' UPDATE ', ' DELETE ', ' DROP ', ' TRUNCATE ', ' ALTER ', 
        ' CREATE ', ' EXEC ', ' EXECUTE ',
        ' SLEEP(', ' BENCHMARK(', ' WAITFOR ', 
        ' EXTRACTVALUE(', ' UPDATEXML(', ' LOAD_FILE(', 
        ' INTO OUTFILE', ' INTO DUMPFILE',
        '/**/', '/*!',
    ];

    $mfcwBlocked = false;
    $blockedParam = '';

    foreach ($mfcwAllParams as $key => $value) {
        if (!is_string($value)) continue;
        $valueUpper = strtoupper($value);
        foreach ($sqlInjectionPatterns as $pattern) {
            if (strpos($valueUpper, strtoupper($pattern)) !== false) {
                $mfcwBlocked = true;
                $blockedParam = $key;
                break 2;
            }
        }
    }

    // 特别检查 keywords 参数
    if (isset($mfcwAllParams['keywords'])) {
        $kw = $mfcwAllParams['keywords'];
        if (preg_match('/[\'";\\\\]/', $kw) || 
            preg_match('/\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b/i', $kw)) {
            $mfcwBlocked = true;
            $blockedParam = 'keywords';
        }
    }

    // 特别检查 account 参数（登录接口）
    if (isset($mfcwAllParams['account'])) {
        $acc = $mfcwAllParams['account'];
        if (preg_match('/[\'";\\\\]/', $acc) || 
            preg_match('/\b(OR|AND|UNION|SELECT)\b/i', $acc)) {
            $mfcwBlocked = true;
            $blockedParam = 'account';
        }
    }

    if ($mfcwBlocked) {
        logAttack('sql_injection', array_merge($mfcwAllParams, ['_blocked_param' => $blockedParam]));
        blockResponse('检测到SQL注入攻击，已记录');
    }
}

// ============================================================
// 工具函数
// ============================================================

function logAttack($type, $params) {
    // 从 cookies 中提取 JWT token 和用户信息
    $userId = 'unknown';
    $userName = 'unknown';
    $jwtToken = '';
    
    // 从 Authorization header 获取 token
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $jwtToken = str_replace('JWT ', '', $_SERVER['HTTP_AUTHORIZATION']);
    }
    
    // 从 cookies 获取 token（ZJMF_ 开头的 cookie）
    if (empty($jwtToken)) {
        foreach ($_COOKIE as $key => $value) {
            if (strpos($key, 'ZJMF_') === 0 && !empty($value)) {
                $jwtToken = $value;
                break;
            }
        }
    }
    
    // 解析 JWT payload 获取用户信息
    if (!empty($jwtToken)) {
        $parts = explode('.', $jwtToken);
        if (count($parts) === 3) {
            $payload = $parts[1];
            // 补齐 base64 长度
            $payload = str_replace(['-', '_'], ['+', '/'], $payload);
            $payload .= str_repeat('=', 4 - strlen($payload) % 4);
            $decoded = base64_decode($payload);
            if ($decoded) {
                $jwtData = json_decode($decoded, true);
                if (isset($jwtData['userinfo']['id'])) {
                    $userId = $jwtData['userinfo']['id'];
                }
                if (isset($jwtData['userinfo']['username'])) {
                    $userName = $jwtData['userinfo']['username'];
                }
            }
        }
    }
    
    // 获取 PHPSESSID
    $sessionId = $_COOKIE['PHPSESSID'] ?? 'unknown';
    
    $logEntry = sprintf(
        "============ [security][%s] ============" . PHP_EOL .
        "时间: %s" . PHP_EOL .
        "用户ID: %s" . PHP_EOL .
        "用户名: %s" . PHP_EOL .
        "IP: %s" . PHP_EOL .
        "真实IP: %s" . PHP_EOL .
        "请求路径: %s" . PHP_EOL .
        "浏览器: %s" . PHP_EOL .
        "会话ID: %s" . PHP_EOL .
        "来源: %s" . PHP_EOL .
        "参数: %s" . PHP_EOL,
        $type,
        date('Y-m-d H:i:s'),
        $userId,
        $userName,
        (string)(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown'),
        (string)(isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : ''),
        (string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'),
        (string)(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
        $sessionId,
        (string)(isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : ''),
        json_encode($params, JSON_UNESCAPED_UNICODE)
    );
    
    // 保存到补丁同目录的 zjmf_security.log
    $logFile = __DIR__ . '/zjmf_security.log';
    @file_put_contents($logFile, $logEntry . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function blockResponse($customMsg = '') {
    if (function_exists('http_response_code')) {
        http_response_code(400);
    } else {
        header('HTTP/1.1 400 Bad Request');
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if (!empty($customMsg)) {
        $msg = $customMsg;
    } else {
        $taunts = [
            '你0元购你妈逼呢，小乐子，被我拦下来了吧哈哈哈',
            '小朋友，0元购是违法的哦，已割掉你的牛子',
            '检测到白嫖狗一只，拦截成功',
            '你的小把戏被发现了呢，要不要找叔叔请你喝杯茶',
            '零元购你是来搞笑的吧',
            '抱歉，本店不支持乞丐模式',
            '你的智商似乎不足以完成这次攻击',
            '温馨提示：免费的东西最贵，比如你的时间',
        ];
        $msg = $taunts[array_rand($taunts)];
    }

    echo json_encode(array(
        'status' => 400,
        'msg' => $msg,
    ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
