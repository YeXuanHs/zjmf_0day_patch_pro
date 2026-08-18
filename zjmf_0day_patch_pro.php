<?php
/**
 * zjmf_0day_patch_pro（魔方财务漏洞修复补丁 Pro版）
 * 
 * 功能：
 * 1. 零元购漏洞拦截（resource_percent_value 等价格操控参数）
 * 2. SQL注入防护（keywords、account 等）
 * 3. 注册验证码强制（图形验证码 + 短信/邮箱验证码）
 * 4. 改密安全加固（拦截未携带旧密码的请求）
 * 5. 开放重定向防护（redirect_url 仅允许站内域名）
 * 6. 上游信息隐藏（ob_start 过滤）
 * 7. 可选关闭整个 /v1 目录
 * 
 * 加载方式：在 /public/index.php 的 require base.php 之后加一行：
 * require CMF_ROOT . 'zjmf_0day_patch_pro.php';
 */

// ============================================================
// 配置区（按需修改）
// ============================================================

// 是否关闭整个 /v1 目录（true=关闭，false=保留）
$disableV1 = false;

// 是否启用上游信息隐藏（true=启用，false=关闭）
$enableUpstreamHide = true;

// 允许的站内域名（开放重定向防护白名单）
$allowedDomains = [
    $_SERVER['HTTP_HOST'] ?? '',
    'www.' . ($_SERVER['HTTP_HOST'] ?? ''),
];

// 短信/邮件发送频率限制（每60秒最多发送次数，0=不限制）
$smsRateLimit = 3;

// ============================================================

if (PHP_SAPI === 'cli') {
    return;
}

if (!defined('CMF_ROOT')) {
    return;
}

// ============================================================
// 1. 上游信息隐藏（ob_start）
// ============================================================
if ($enableUpstreamHide) {
    @ini_set('zlib.output_compression', 'Off');
    if (function_exists('apache_setenv')) {
        @apache_setenv('no-gzip', '1');
    }

    $upstreamHideWhitelist = [];
    $dbConfigPath = CMF_ROOT . 'app/config/database.php';
    if (file_exists($dbConfigPath)) {
        $dbConfig = include $dbConfigPath;
        if (is_array($dbConfig) && !empty($dbConfig['admin_application'])) {
            $upstreamHideWhitelist[] = '/' . $dbConfig['admin_application'] . '/';
            $upstreamHideWhitelist[] = '/' . $dbConfig['admin_application'];
        }
    }

    $upstreamHideFields = [
        'api_type', 'upstream_product_shopping_url', 'upstream_pid',
        'upstream_version', 'upstream_price_type', 'upstream_price_value',
        'upstream_qty', 'upstream_stock_control', 'upstream_ontrial_status',
        'upstream_price', 'upstream_cycle', 'zjmf_api_id', 'upstream_auto_setup',
    ];

    $upstreamReplaceValues = [
        'api_type' => 'normal', 'zjmf_api_id' => 0, 'upstream_pid' => 0,
        'upstream_version' => 0, 'upstream_auto_setup' => '',
        'upstream_ontrial_status' => 0, 'upstream_stock_control' => 0,
        'upstream_qty' => 0, 'upstream_price' => '0.00',
        'upstream_cycle' => zjmfGetTaunt('upstream'),
        'upstream_price_type' => null,
        'upstream_price_value' => zjmfGetTaunt('upstream'),
    ];

    function upstreamHideCleanArray(&$data, $hideFields, $replaceValues)
    {
        if (!is_array($data)) return;
        
        foreach ($data as $key => &$value) {
            if (is_array($value)) {
                upstreamHideCleanArray($value, $hideFields, $replaceValues);
            }
            $strKey = (string)$key;
            if (in_array($strKey, $hideFields, true)) {
                if ($strKey === 'upstream_product_shopping_url') {
                    $data[$key] = zjmfGetTaunt('upstream');
                } elseif (isset($replaceValues[$strKey])) {
                    $data[$key] = $replaceValues[$strKey];
                } else {
                    $data[$key] = zjmfGetTaunt('upstream');
                }
            }
            if ($strKey === 'upstream_id' && is_numeric($value) && $value != 0) {
                $data[$key] = 0;
            }
            if ($strKey === 'upper_reaches_id' && is_numeric($value) && $value != 0) {
                $data[$key] = 0;
            }
        }
        unset($value);
    }

    function upstreamHideTryDecompress($buffer)
    {
        if (strlen($buffer) < 2) return $buffer;
        $b0 = ord($buffer[0]);
        $b1 = isset($buffer[1]) ? ord($buffer[1]) : 0;
        if ($b0 === 0x1f && $b1 === 0x8b) {
            $decoded = @gzdecode($buffer);
            if ($decoded !== false) return $decoded;
        }
        if ($b0 === 0x78 && ($b1 === 0x01 || $b1 === 0x5e || $b1 === 0x9c)) {
            $decoded = @gzuncompress($buffer);
            if ($decoded !== false) return $decoded;
        }
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            if (function_exists('inflate_init') && function_exists('inflate_add')) {
                $context = @inflate_init(ZLIB_ENCODING_DEFLATE);
                if ($context !== false) {
                    $decoded = @inflate_add($context, $buffer);
                    if ($decoded !== false) return $decoded;
                }
            }
        } else {
            $decoded = @gzinflate($buffer);
            if ($decoded !== false) return $decoded;
        }
        return $buffer;
    }

    function upstreamHideFilter($buffer)
    {
        global $upstreamHideFields, $upstreamReplaceValues, $upstreamHideWhitelist;
        if (!empty($upstreamHideWhitelist)) {
            $requestUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
            if (!empty($requestUri)) {
                foreach ($upstreamHideWhitelist as $whitelistPath) {
                    if (stripos($requestUri, $whitelistPath) !== false) return $buffer;
                }
            }
        }
        if (empty($buffer)) return $buffer;
        $rawBuffer = $buffer;
        $trimmed = trim($buffer);
        if (strlen($trimmed) < 2) return $buffer;
        $firstChar = $trimmed[0];
        if ($firstChar !== '{' && $firstChar !== '[') {
            $buffer = upstreamHideTryDecompress($rawBuffer);
            $trimmed = trim($buffer);
            if (strlen($trimmed) < 2 || ($trimmed[0] !== '{' && $trimmed[0] !== '[')) {
                return $rawBuffer;
            }
        }
        $json = json_decode($trimmed, true);
        if (json_last_error() !== JSON_ERROR_NONE) return $rawBuffer;
        if (!is_array($json)) return $rawBuffer;
        upstreamHideCleanArray($json, $upstreamHideFields, $upstreamReplaceValues);
        $newBuffer = json_encode($json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
        return ($newBuffer !== false) ? $newBuffer : $rawBuffer;
    }

    ob_start('upstreamHideFilter');
}

// ============================================================
// 2. 获取请求信息
// ============================================================
$mfcwMethod = strtoupper((string)(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET'));
$mfcwPath = parse_url(
    (string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'),
    PHP_URL_PATH
);
if (!is_string($mfcwPath) || $mfcwPath === '') $mfcwPath = '/';
$mfcwPath = preg_replace('#^/index\.php#i', '', $mfcwPath);
$mfcwPath = '/' . trim($mfcwPath, '/');

$mfcwAction = isset($_GET['action']) ? $_GET['action'] : (isset($_POST['action']) ? $_POST['action'] : '');
$mfcwStatusCart = isset($_GET['statuscart']) ? $_GET['statuscart'] : (isset($_POST['statuscart']) ? $_POST['statuscart'] : '');

// 读取 JSON body
$mfcwJsonBody = null;
if (strpos(strtolower((string)(isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '')), 'application/json') !== false) {
    $mfcwRawBody = file_get_contents('php://input');
    if (is_string($mfcwRawBody) && $mfcwRawBody !== '') {
        $mfcwJsonBody = json_decode($mfcwRawBody, true);
    }
}
$mfcwAllParams = array_merge($_GET, $_POST, is_array($mfcwJsonBody) ? $mfcwJsonBody : []);

// ============================================================
// 3. 可选关闭 /v1 目录
// ============================================================
if ($disableV1) {
    $mfcwV1Path = $mfcwPath;
    for ($round = 0; $round < 3; $round++) {
        $decoded = rawurldecode($mfcwV1Path);
        if ($decoded === $mfcwV1Path) break;
        $mfcwV1Path = $decoded;
    }
    $mfcwV1Path = str_replace('\\', '/', $mfcwV1Path);
    $mfcwV1Path = preg_replace('#/+#', '/', $mfcwV1Path);
    $mfcwV1Path = rtrim($mfcwV1Path, '/');

    if (preg_match('#^/v1(?:/|$)#i', $mfcwV1Path) === 1) {
        http_response_code(404);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode(['status' => 404, 'msg' => 'Not Found'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// ============================================================
// 4. 零元购漏洞拦截
// ============================================================
$mfcwIsCheckout = (
    $mfcwPath === '/cart'
    && $mfcwAction === 'viewcart'
    && $mfcwStatusCart === 'checkout'
) || $mfcwPath === '/cart/settle'
  || $mfcwPath === '/v1/cart/checkout';

if ($mfcwIsCheckout && $mfcwMethod === 'POST') {
    $dangerousPriceParams = [
        'resource_percent_value', 'resource_percent', 'percent_value',
        'discount_percent', 'price_percent', 'custom_price',
        'override_price', 'price_override', 'amount_override',
    ];
    foreach ($dangerousPriceParams as $param) {
        if (array_key_exists($param, $mfcwAllParams)) {
            zjmfLogAttack('zero_cost', $mfcwAllParams);
            zjmfBlockResponse('', 'zero_cost');
        }
    }
}

// ============================================================
// 5. SQL注入防护
// ============================================================
$mfcwIsSqlVulnerable = (
    $mfcwPath === '/v1/funds'
    || $mfcwPath === '/v1/login'
    || $mfcwPath === '/v1/login_api'
    || $mfcwPath === '/login'
    || $mfcwPath === '/v1/register'
    || $mfcwPath === '/register'
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
        ' INTO OUTFILE', ' INTO DUMPFILE', ' INFORMATION_SCHEMA',
        '/**/', '/*!',
    ];

    // 排除的参数（密码、验证码、邮箱等可能包含特殊字符的字段）
    $excludeParams = [
        'password', 'old_password', 'new_password', 'repassword',
        'checkPassword', 'confirm_password', 'captcha', 'code',
        'sms_code', 'phone_code', 'email_code', 'verify_code',
        'email', 'mail', 'e_mail',
    ];

    $mfcwBlocked = false;
    $blockedParam = '';

    foreach ($mfcwAllParams as $key => $value) {
        if (!is_string($value)) continue;
        // 跳过排除的参数
        if (in_array($key, $excludeParams)) continue;
        $valueUpper = strtoupper($value);
        foreach ($sqlInjectionPatterns as $pattern) {
            if (strpos($valueUpper, strtoupper($pattern)) !== false) {
                $mfcwBlocked = true;
                $blockedParam = $key;
                break 2;
            }
        }
    }

    if (isset($mfcwAllParams['keywords'])) {
        $kw = $mfcwAllParams['keywords'];
        if (preg_match('/[\'";\\\\]/', $kw) ||
            preg_match('/\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b/i', $kw)) {
            $mfcwBlocked = true;
            $blockedParam = 'keywords';
        }
    }

    if (isset($mfcwAllParams['account'])) {
        $acc = $mfcwAllParams['account'];
        if (preg_match('/[\'";\\\\]/', $acc) ||
            preg_match('/\b(OR|AND|UNION|SELECT)\b/i', $acc)) {
            $mfcwBlocked = true;
            $blockedParam = 'account';
        }
    }

    if ($mfcwBlocked) {
        zjmfLogAttack('sql_injection', array_merge($mfcwAllParams, ['_blocked_param' => $blockedParam]));
        zjmfBlockResponse('', 'sql_injection');
    }
}

// ============================================================
// 7. 注册验证码强制（防止绕过验证码注册）
// ============================================================
$mfcwIsRegister = (
    $mfcwPath === '/v1/register'
    || $mfcwPath === '/register'
    || $mfcwPath === '/registerPhone'
    || $mfcwPath === '/registerEmail'
    || ($mfcwPath === '/login' && $mfcwAction === 'register')
);

if ($mfcwIsRegister && $mfcwMethod === 'POST') {
    // 检查是否开启了图形验证码（通过配置文件读取，避免依赖 ThinkPHP）
    $captchaConfig = CMF_ROOT . 'app/config/session.php';
    $isCaptcha = 0;
    if (function_exists('configuration')) {
        $isCaptcha = intval(configuration('is_captcha'));
    }
    
    if ($isCaptcha == 1) {
        $captcha = $mfcwAllParams['captcha'] ?? '';
        $idtoken = $mfcwAllParams['idtoken'] ?? '';
        
        // 只检查参数是否存在，实际验证由系统完成
        if (empty($captcha) || empty($idtoken)) {
            zjmfLogAttack('register_captcha_bypass', $mfcwAllParams);
            zjmfBlockResponse('', 'captcha_bypass');
        }
    }
}

// ============================================================
// 8. 短信/邮件轰炸防护（强制验证码校验）
// ============================================================
// 拦截所有发送验证码的接口
$mfcwIsSendCode = (
    strpos($mfcwPath, 'Send') !== false
    || strpos($mfcwPath, 'send') !== false
    || $mfcwPath === '/v1/code'
    || $mfcwPath === '/login/send_sms'
    || $mfcwPath === '/login/send_email'
    || $mfcwPath === '/v1/send'
);

if ($mfcwIsSendCode && $mfcwMethod === 'POST') {
    $isCaptcha = 0;
    if (function_exists('configuration')) {
        $isCaptcha = intval(configuration('is_captcha'));
    }
    if ($isCaptcha == 1) {
        $captcha = $mfcwAllParams['captcha'] ?? '';
        $idtoken = $mfcwAllParams['idtoken'] ?? '';
        
        // 只检查参数是否存在，实际验证由系统完成
        if (empty($captcha) || empty($idtoken)) {
            zjmfLogAttack('sms_bomb', $mfcwAllParams);
            zjmfBlockResponse('', 'sms_bomb');
        }
    }
    
    // 短信/邮件发送频率限制
    if ($smsRateLimit > 0) {
        $target = $mfcwAllParams['phone'] ?? $mfcwAllParams['phonenumber'] ?? $mfcwAllParams['email'] ?? '';
        if (!empty($target)) {
            $rateFile = __DIR__ . '/zjmf_sms_rate.json';
            $rateData = [];
            if (file_exists($rateFile)) {
                $rateData = json_decode(file_get_contents($rateFile), true) ?: [];
            }
            
            $now = time();
            $targetHash = md5($target);
            
            // 清理过期记录
            if (isset($rateData[$targetHash])) {
                $rateData[$targetHash] = array_filter($rateData[$targetHash], function($ts) use ($now) {
                    return ($now - $ts) < 60;
                });
            }
            
            // 检查频率
            $count = isset($rateData[$targetHash]) ? count($rateData[$targetHash]) : 0;
            if ($count >= $smsRateLimit) {
                zjmfLogAttack('sms_rate_limit', ['target' => $target, 'count' => $count]);
                zjmfBlockResponse('', 'rate_limit');
            }
            
            // 记录本次发送
            $rateData[$targetHash][] = $now;
            @file_put_contents($rateFile, json_encode($rateData), LOCK_EX);
        }
    }
}

// ============================================================
// 9. 改密安全加固
// ============================================================
$mfcwIsPasswordChange = (
    $mfcwPath === '/v1/password'
    || $mfcwPath === '/modify_password'
    || $mfcwPath === '/password'
);

if ($mfcwIsPasswordChange && $mfcwMethod === 'POST') {
    $oldPassword = $mfcwAllParams['old_password'] ?? '';
    $flag = isset($mfcwAllParams['flag']) ? intval($mfcwAllParams['flag']) : 0;

    // flag != 1 时跳过旧密码验证，这是漏洞
    if ($flag !== 1 && empty($oldPassword)) {
        zjmfLogAttack('password_bypass', ['flag' => $flag, 'path' => $mfcwPath]);
        zjmfBlockResponse('', 'password_bypass');
    }
}

// ============================================================
// 10. 开放重定向防护
// ============================================================
$mfcwRedirectUrl = $mfcwAllParams['redirect_url'] ?? $mfcwAllParams['redirect'] ?? $mfcwAllParams['return_url'] ?? '';

if (!empty($mfcwRedirectUrl)) {
    $isAllowed = false;

    // 检查是否是相对路径
    if (strpos($mfcwRedirectUrl, '/') === 0 && strpos($mfcwRedirectUrl, '//') !== 0) {
        $isAllowed = true;
    }

    // 检查是否是允许的域名
    if (!$isAllowed) {
        $parsedUrl = parse_url($mfcwRedirectUrl);
        if (!empty($parsedUrl['host'])) {
            foreach ($allowedDomains as $domain) {
                if (!empty($domain) && strtolower($parsedUrl['host']) === strtolower($domain)) {
                    $isAllowed = true;
                    break;
                }
            }
        }
    }

    // 检查协议相对绕过 //evil.com
    if (!$isAllowed && strpos($mfcwRedirectUrl, '//') === 0) {
        $domain = parse_url('https:' . $mfcwRedirectUrl, PHP_URL_HOST);
        foreach ($allowedDomains as $allowedDomain) {
            if (!empty($allowedDomain) && strtolower($domain) === strtolower($allowedDomain)) {
                $isAllowed = true;
                break;
            }
        }
    }

    if (!$isAllowed) {
        zjmfLogAttack('open_redirect', ['redirect_url' => $mfcwRedirectUrl]);
        zjmfBlockResponse('', 'open_redirect');
    }
}

// ============================================================
// 工具函数
// ============================================================

function zjmfLogAttack($type, $params)
{
    $userId = 'unknown';
    $userName = 'unknown';
    $jwtToken = '';

    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $jwtToken = str_replace('JWT ', '', $_SERVER['HTTP_AUTHORIZATION']);
    }

    if (empty($jwtToken)) {
        foreach ($_COOKIE as $key => $value) {
            if (strpos($key, 'ZJMF_') === 0 && !empty($value)) {
                $jwtToken = $value;
                break;
            }
        }
    }

    if (!empty($jwtToken)) {
        $parts = explode('.', $jwtToken);
        if (count($parts) === 3) {
            $payload = $parts[1];
            $payload = str_replace(['-', '_'], ['+', '/'], $payload);
            $payload .= str_repeat('=', 4 - strlen($payload) % 4);
            $decoded = base64_decode($payload);
            if ($decoded) {
                $jwtData = json_decode($decoded, true);
                if (isset($jwtData['userinfo']['id'])) $userId = $jwtData['userinfo']['id'];
                if (isset($jwtData['userinfo']['username'])) $userName = $jwtData['userinfo']['username'];
            }
        }
    }

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

    $logFile = __DIR__ . '/zjmf_security.log';
    @file_put_contents($logFile, $logEntry . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function zjmfBlockResponse($customMsg = '', $attackType = '')
{
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
        $msg = zjmfGetTaunt($attackType);
    }

    echo json_encode(array(
        'status' => 400,
        'msg' => $msg,
    ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// ============================================================
// 嘲讽文案配置（统一管理）
// ============================================================

/**
 * 获取随机嘲讽文案
 * @param string $type 攻击类型
 * @return string 随机嘲讽文案
 */
function zjmfGetTaunt($type = '')
{
    // 所有嘲讽文案集中在这里管理
    $taunts = [
        // 0元购
        'zero_cost' => [
            '你0元购你妈逼呢，小乐子，被我拦下来了吧哈哈哈',
            '小朋友，0元购是违法的哦，已割掉你的牛子',
            '检测到白嫖狗一只，拦截成功',
            '零元购你是来搞笑的吧',
            '抱歉，本店不支持乞丐模式',
            '温馨提示：免费的东西最贵，比如你的时间',
        ],
        // 改密绕过
        'password_bypass' => [
            '想改别人密码？先把你自己的脑子改改吧',
            '不带旧密码就想改密？你是在做梦吗',
            '检测到密码修改绕过尝试，你是不是觉得管理员是傻子',
            '没有旧密码就想改密，你是来送人头的吧',
            '密码修改需要旧密码，这不是常识吗',
        ],
        // 图形验证码绕过
        'captcha_bypass' => [
            '没有图形验证码就想操作？你是在逗我吗',
            '图形验证码都不填就想通过？你是不是太天真了',
            '检测到图形验证码绕过尝试，你的小把戏被发现了',
            '没有图形验证码，你连门都进不来',
            '图形验证码是干嘛的？就是防你这种人的',
            '想绕过图形验证码？你还不够格',
        ],
        // SQL注入
        'sql_injection' => [
            'SQL注入？你是从2010年穿越来的吗',
            '检测到SQL注入攻击，你的技术还停留在上个世纪',
            '想注入？先把你的注入语法学学好吧',
            'SQL注入已经被我们拦截了，你还是放弃吧',
            '你的注入 payload 太垃圾了，我都懒得看',
        ],
        // 开放重定向
        'open_redirect' => [
            '想把用户跳转到你那儿？做梦吧',
            '检测到开放重定向攻击，你的钓鱼网站暴露了',
            'redirect_url 只允许站内跳转，你死心吧',
            '想偷登录令牌？你还不够格',
        ],
        // 短信/邮件轰炸
        'sms_bomb' => [
            '想发短信轰炸？先过图形验证码这关吧',
            '没有图形验证码就想发短信？你是在浪费大家时间',
            '检测到短信轰炸尝试，你的手机号已经被记录了',
            '图形验证码都不过就想发短信？你是来搞笑的吧',
        ],
        // 频率限制
        'rate_limit' => [
            '发太快了，休息一下吧，你累不累啊',
            '60秒内只能发这么多，你急什么急',
            '检测到频率超限，你是在测试我们的限流吗',
            '慢慢来，别着急，验证码又不会跑掉',
        ],
        // 路径遍历
        'path_traversal' => [
            '想读取系统文件？你是在做梦吗',
            '检测到路径遍历攻击，你是不是觉得我们服务器是裸奔的',
            '../ 你以为很有用？我们早防着了',
            '想穿越目录？你穿越剧看多了吧',
        ],
        // XSS攻击
        'xss' => [
            '想注入脚本？你是在侮辱我们的安全防护吗',
            '检测到XSS攻击，你的 alert() 弹不出来的',
            'XSS？你以为我们会让你的脚本跑起来？',
            '想偷cookie？你还不够格',
        ],
        // 暴力破解
        'brute_force' => [
            '密码错误太多次了，你是在猜密码吗',
            '检测到暴力破解尝试，你的IP已经被记录了',
            '猜密码？你不如去买彩票',
            '暴力破解是最低级的攻击方式，你也就这点水平',
        ],
        // 文件上传攻击
        'file_upload' => [
            '想上传恶意文件？你是在做梦吗',
            '检测到文件上传攻击，你的webshell传不上来的',
            '文件类型不合法，你以为我们会让你传可执行文件？',
            '想传木马？你还是省省吧',
        ],
        // 命令注入
        'command_injection' => [
            '想执行系统命令？你是在搞笑吗',
            '检测到命令注入攻击，你是不是觉得我们服务器是裸奔的',
            '命令注入？你以为我们会让你跑命令？',
            '想反弹shell？你还不够格',
        ],
        // 上游信息隐藏
        'upstream' => [
            '不给你看上游气不气',
            '上游信息已隐藏，你猜猜是谁',
            '想知道上游？做梦吧',
            '上游是谁？你猜啊',
            '上游信息属于商业机密，不对外公开',
            '别打上游的主意了，你找不到的',
            '上游信息已脱敏，请勿窥探',
            '你永远不知道我们的上游是谁',
        ],
        // 默认（未知攻击类型）
        'default' => [
            '检测到异常请求，已拦截',
            '你的攻击被发现了，要不要找叔叔喝杯茶',
            '你的智商似乎不足以完成这次攻击',
            '别白费力气了，我们有防护',
        ],
    ];

    // 根据类型返回随机嘲讽
    if (!empty($type) && isset($taunts[$type])) {
        return $taunts[$type][array_rand($taunts[$type])];
    }
    
    return $taunts['default'][array_rand($taunts['default'])];
}
