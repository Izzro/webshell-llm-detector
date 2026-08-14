<?php
/**
 * 困难良性样本：支付网关客户端 - 合法使用 base64_decode
 *
 * 业务场景：支付 webhook 中订单数据以 base64 编码传输，
 * API 密钥也以 base64 存储于配置中。
 *
 * 为什么安全：
 *   1. base64_decode 仅解码数据，结果经 JSON 解析，不传入 eval/system。
 *   2. 解码数据来自受信任网关或本地配置，非用户直接输入。
 *   3. 解码后经过严格的结构和类型校验。
 *   4. base64 是编码方案，解码不触发代码执行。
 */

class PaymentGatewayClient
{
    const ENCODED_API_KEY = 'c2VjcmV0X2FwaV9rZXlfMTIzNDU2';
    const ENCODED_MERCHANT_ID = 'bWVyY2hhbnRfMDA5OTE4ODI=';

    /**
     * 从 webhook 提取订单数据
     * @param string $rawBody webhook 原始 body
     * @return array 订单数据
     */
    public function parseWebhook($rawBody)
    {
        $envelope = json_decode($rawBody, true);
        if ($envelope === null || !isset($envelope['data'])) {
            throw new RuntimeException('无效的 webhook 格式');
        }

        // 验证签名：base64 解码密钥后计算 HMAC
        $apiKey = base64_decode(self::ENCODED_API_KEY);
        $expectedSig = hash_hmac('sha256', $envelope['data'], $apiKey);
        if (!hash_equals($expectedSig, $envelope['signature'])) {
            throw new RuntimeException('签名验证失败');
        }

        // 解码订单数据：decode 后直接 json_decode，不进 eval
        $decoded = base64_decode($envelope['data']);
        if ($decoded === false) {
            throw new RuntimeException('数据解码失败');
        }

        $order = json_decode($decoded, true);
        if ($order === null) {
            throw new RuntimeException('JSON 解析失败');
        }

        // 结构和类型校验
        foreach (array('order_id', 'amount', 'currency') as $f) {
            if (!array_key_exists($f, $order)) {
                throw new RuntimeException("缺少字段: {$f}");
            }
        }
        if (!is_string($order['order_id']) || !is_numeric($order['amount'])) {
            throw new RuntimeException('字段类型不匹配');
        }
        return $order;
    }

    /**
     * 构建签名头（密钥经 base64 解码后用于 HMAC）
     */
    public function buildAuthHeaders($payload)
    {
        $key = base64_decode(self::ENCODED_API_KEY);
        $merchant = base64_decode(self::ENCODED_MERCHANT_ID);
        $ts = time();
        $sig = hash_hmac('sha256', $merchant . $ts . $payload, $key);
        return array('X-Merchant-Id' => $merchant, 'X-Timestamp' => $ts, 'X-Signature' => $sig);
    }
}

// 使用示例
$client = new PaymentGatewayClient();
try {
    $order = $client->parseWebhook(file_get_contents('php://input'));
    error_log("订单: {$order['order_id']} 金额: {$order['amount']}");
    echo 'OK';
} catch (Exception $e) {
    http_response_code(400);
    echo 'Bad Request';
}
