<?php
/**
 * 困难良性样本：基于 create_function 的旧式路由分发器
 *
 * 业务场景：遗留系统(PHP 5.2)用 create_function 创建匿名回调，
 * 处理 API 版本间的数据格式转换。映射存于类内部固定数组。
 *
 * 为什么安全：
 *   1. create_function 参数来自类内硬编码映射数组，用户输入不参与。
 *   2. 用户 $action 仅作数组键查找，无法影响函数体内容。
 *   3. 未知 action 被拒绝，不存在动态构造函数体的路径。
 *
 * 注意：create_function 在 PHP 7.2 废弃、8.0 移除，仅用于检测器测试。
 */

class LegacyApiDispatcher
{
    // 处理器映射表：均为开发人员编写的固定代码
    private static $handlers = array(
        'v1_to_v2' => array(
            'params' => '$data',
            'body'   => '
                $r = array();
                foreach ($data as $k => $v) {
                    $r[preg_replace("/_([a-z])/", "", $k)] = $v;
                }
                return $r;
            '
        ),
        'v2_to_v1' => array(
            'params' => '$data',
            'body'   => '
                $r = array();
                foreach ($data as $k => $v) {
                    $r[strtolower(preg_replace("/([A-Z])/", "_$1", $k))] = $v;
                }
                return $r;
            '
        ),
    );

    private $cache = array();

    /**
     * 分发请求到格式转换处理器
     * @param string $action 转换类型（必须命中白名单）
     * @param array  $data   待转换数据（仅作参数传入，不影响函数定义）
     */
    public function dispatch($action, array $data)
    {
        // 白名单校验
        if (!isset(self::$handlers[$action])) {
            throw new InvalidArgumentException("未知类型: {$action}");
        }

        // 首次调用时创建函数（参数来自内部数组）
        if (!isset($this->cache[$action])) {
            $cfg = self::$handlers[$action];
            $this->cache[$action] = create_function($cfg['params'], $cfg['body']);
        }

        // $data 作为参数传入，不影响函数定义
        return call_user_func($this->cache[$action], $data);
    }
}

// 使用示例
$dispatcher = new LegacyApiDispatcher();
$action = isset($_GET['action']) ? $_GET['action'] : '';
$inputData = isset($_POST['data']) ? $_POST['data'] : array();

try {
    $output = $dispatcher->dispatch($action, $inputData);
    header('Content-Type: application/json');
    echo json_encode($output);
} catch (InvalidArgumentException $e) {
    http_response_code(400);
    echo htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}
