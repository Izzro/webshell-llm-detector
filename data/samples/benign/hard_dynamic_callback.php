<?php
/**
 * 困难良性样本：基于白名单的动态回调分发器
 *
 * 业务场景：CMS 插件系统，前端通过参数指定回调名称，
 * 后端从预注册白名单中查找并执行。类似 WordPress apply_filters。
 *
 * 为什么安全：
 *   1. call_user_func 的函数名来自类内部白名单数组，
 *      用户名称仅作数组键查找，不存在则拒绝。
 *   2. 白名单中的函数均为开发人员注册的安全闭包。
 *   3. 即使传入 'system' 等恶意名称，因不在白名单中被拦截。
 *   4. 回调参数经过类型检查。
 */

class CallbackRegistry
{
    // 已注册的回调白名单（用户无法修改此数组）
    private $callbacks = array();

    public function __construct()
    {
        $this->register('trim_text', function($text) {
            return trim(strip_tags($text));
        });
        $this->register('upper_text', function($text) {
            return strtoupper(trim($text));
        });
        $this->register('slugify', function($text) {
            $text = strtolower(trim($text));
            return trim(preg_replace('/[^a-z0-9]+/', '-', $text), '-');
        });
        $this->register('format_price', function($value) {
            return number_format((float)$value, 2, '.', ',');
        });
        $this->register('format_date', function($ts) {
            $ts = is_numeric($ts) ? (int)$ts : strtotime($ts);
            return date('Y-m-d', $ts);
        });
    }

    /**
     * 注册回调（仅限内部调用）
     */
    private function register($name, $callback)
    {
        if (!is_callable($callback)) {
            throw new InvalidArgumentException("回调不可调用: {$name}");
        }
        $this->callbacks[$name] = $callback;
    }

    /**
     * 根据名称调用已注册的回调
     * @param string $name 回调名（必须命中白名单）
     * @param mixed  $arg  回调参数
     */
    public function apply($name, $arg)
    {
        // 白名单校验：回调名必须存在于已注册列表
        if (!isset($this->callbacks[$name])) {
            throw new InvalidArgumentException("未注册的回调: {$name}");
        }

        $callback = $this->callbacks[$name];
        if (!is_callable($callback)) {
            throw new RuntimeException("回调不可调用: {$name}");
        }

        // 安全调用：函数名来自白名单
        return call_user_func($callback, $arg);
    }

    public function getAvailable()
    {
        return array_keys($this->callbacks);
    }
}

// 使用示例
$registry = new CallbackRegistry();
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'trim_text';
$value  = isset($_GET['value']) ? $_GET['value'] : '';

try {
    $result = $registry->apply($filter, $value);
    echo htmlspecialchars($result, ENT_QUOTES, 'UTF-8');
} catch (InvalidArgumentException $e) {
    $available = implode(', ', $registry->getAvailable());
    http_response_code(400);
    echo "无效过滤器。可用: {$available}";
}
