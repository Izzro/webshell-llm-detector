<?php
/**
 * 困难良性样本：使用 assert 进行参数前置校验
 *
 * 业务场景：退款服务在处理请求前用 assert 校验参数类型和范围。
 *
 * 为什么安全：
 *   1. assert 传入的是布尔表达式（函数返回值），不是代码字符串。
 *   2. 用户输入仅作为参数传入 is_string/is_numeric 等校验函数，
 *      不拼入 assert 表达式。
 *   3. 断言失败仅抛出 AssertionError，不执行任意代码。
 *   4. 生产环境可通过 zend.assertions=0 关闭断言。
 */

class RefundService
{
    /**
     * 处理退款请求
     * @param mixed $orderId   订单号
     * @param mixed $amount    退款金额
     * @param mixed $reason    退款原因
     * @param mixed $operatorId 操作人ID
     * @return array 退款结果
     */
    public function processRefund($orderId, $amount, $reason, $operatorId)
    {
        // 以下 assert 传入布尔值（函数返回值），非代码字符串
        // 用户输入仅作函数参数，不进入 assert 表达式
        assert(is_string($orderId), '订单号必须是字符串');
        assert(preg_match('/^ORD[0-9]{12}$/', $orderId), '订单号格式不合法');

        assert(is_numeric($amount), '退款金额必须是数字');
        assert($amount > 0, '退款金额必须大于零');
        assert($amount <= 100000, '退款金额超出上限');

        assert(is_string($reason), '退款原因必须是字符串');
        assert(mb_strlen($reason) <= 200, '退款原因过长');

        assert(is_int($operatorId), '操作人ID必须是整数');
        assert($operatorId > 0, '操作人ID必须为正数');

        // 业务逻辑
        $record = array(
            'order_id'  => $orderId,
            'amount'    => (float)$amount,
            'reason'    => $reason,
            'operator'  => $operatorId,
            'timestamp' => date('Y-m-d H:i:s'),
            'status'    => 'pending',
        );

        return array('success' => true, 'record' => $record);
    }

    /**
     * 校验商品规格结构
     */
    public function validateSpec(array $spec)
    {
        assert(is_array($spec), '规格必须是数组');
        assert(isset($spec['name']) && is_string($spec['name']), '规格名缺失');
        assert(isset($spec['value']) && is_string($spec['value']), '规格值缺失');
        return true;
    }
}

// 使用示例
$service = new RefundService();
$orderId  = isset($_POST['order_id']) ? $_POST['order_id'] : '';
$amount   = isset($_POST['amount']) ? $_POST['amount'] : 0;
$reason   = isset($_POST['reason']) ? $_POST['reason'] : '';
$operator = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;

try {
    $result = $service->processRefund($orderId, $amount, $reason, $operator);
    echo json_encode($result);
} catch (AssertionError $e) {
    http_response_code(422);
    echo json_encode(array('error' => $e->getMessage()));
}
