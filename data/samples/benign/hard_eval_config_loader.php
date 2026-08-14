<?php
/**
 * 困难良性样本：配置驱动的折扣规则加载器
 *
 * 业务场景：电商促销系统，折扣规则存储在受保护配置文件中，
 * 通过 eval 执行规则计算价格。
 *
 * 为什么安全：
 *   1. eval 输入来自服务器本地配置文件，路径为硬编码常量。
 *   2. 配置文件经过 sha256 签名校验，运行时检测篡改。
 *   3. 用户参数($price)仅作为变量传入作用域，不拼入代码字符串。
 *   4. 规则名经白名单校验，路径经 realpath 防穿越。
 */

class ConfigRuleLoader
{
    const RULE_DIR = __DIR__ . '/config/rules/';

    // 已签名的规则文件白名单（文件名 => 期望 sha256）
    private static $signedRules = array(
        'discount_normal.rule'    => 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        'discount_vip.rule'       => 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
        'discount_wholesale.rule' => 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    );

    /**
     * 加载并执行折扣规则
     * @param string $ruleName 规则名（必须命中白名单）
     * @param float  $price    商品原价（数值，不进入代码字符串）
     */
    public function calculatePrice($ruleName, $price)
    {
        // 白名单校验
        if (!isset(self::$signedRules[$ruleName])) {
            throw new InvalidArgumentException("未知规则: {$ruleName}");
        }

        $ruleFile = self::RULE_DIR . $ruleName;

        // 路径校验：防止 ../ 注入
        $realPath = realpath($ruleFile);
        if ($realPath === false || strpos($realPath, realpath(self::RULE_DIR)) !== 0) {
            throw new InvalidArgumentException("规则文件路径非法");
        }

        $code = file_get_contents($realPath);
        if ($code === false) {
            throw new RuntimeException("无法读取规则文件");
        }

        // 完整性校验：hash 必须匹配
        if (hash('sha256', $code) !== self::$signedRules[$ruleName]) {
            throw new RuntimeException("规则文件可能被篡改");
        }

        // eval 执行：配置内容形如 return $price * 0.8;
        // $price 是数值，不会进入代码字符串本身
        return eval($code);
    }
}

// 使用示例
$loader = new ConfigRuleLoader();
$price = isset($_GET['price']) ? (float)$_GET['price'] : 0.0;
$rule = ($price > 1000) ? 'discount_wholesale.rule' : 'discount_normal.rule';
echo "最终价格: " . $loader->calculatePrice($rule, $price) . "\n";
