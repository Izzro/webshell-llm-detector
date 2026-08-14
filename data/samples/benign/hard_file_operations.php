<?php
/**
 * 困难良性样本：固定路径的日志文件读写
 *
 * 业务场景：审计日志系统，将操作记录写入固定日志文件。
 *
 * 为什么安全：
 *   1. file_get_contents/file_put_contents 路径为硬编码常量
 *      或系统生成的日期文件名，用户输入不参与路径构造。
 *   2. 查询日期参数经 YYYY-MM-DD + checkdate 校验，防穿越。
 *   3. 写入前清理换行符，防日志注入。
 */

class AuditLogger
{
    const LOG_DIR = '/var/log/myapp/audit/';
    const LOG_PREFIX = 'audit_';

    /** 写入审计日志 */
    public function log($level, $message, array $context = array())
    {
        $level = in_array(strtoupper($level), array('INFO','WARN','ERROR','DEBUG'), true) ? strtoupper($level) : 'INFO';
        // 清理换行符，防日志注入
        $message = str_replace(array("\r", "\n"), ' ', substr($message, 0, 1000));
        $ts = date('Y-m-d H:i:s');
        $ctx = $context ? ' ' . json_encode($context, JSON_UNESCAPED_UNICODE) : '';
        $line = "[{$ts}] {$level}: {$message}{$ctx}\n";
        // 文件名按日期生成，路径由系统控制
        $logFile = self::LOG_DIR . self::LOG_PREFIX . date('Y-m-d') . '.log';
        if (!is_dir(self::LOG_DIR)) mkdir(self::LOG_DIR, 0640, true);
        return file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX) !== false;
    }

    /**
     * 读取指定日期的日志
     * @param string $date 日期（YYYY-MM-DD，经严格校验）
     */
    public function readLog($date, $limit = 100)
    {
        // 严格校验日期格式
        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $date, $m)) {
            throw new InvalidArgumentException('日期格式必须是 YYYY-MM-DD');
        }
        if (!checkdate((int)$m[2], (int)$m[3], (int)$m[1])) {
            throw new InvalidArgumentException('日期不合法');
        }
        $ts = strtotime($date);
        if ($ts > time() || $ts < strtotime('-365 days')) {
            throw new InvalidArgumentException('日期超出范围');
        }
        // 路径由校验后的日期构成，无穿越风险
        $logFile = self::LOG_DIR . self::LOG_PREFIX . $date . '.log';
        if (!file_exists($logFile)) return array();
        $content = file_get_contents($logFile);
        if ($content === false) return array();
        $lines = explode("\n", trim($content));
        return ($limit > 0 && count($lines) > $limit) ? array_slice($lines, -$limit) : $lines;
    }
}

// 使用示例
$logger = new AuditLogger();
$logger->log('INFO', '用户登录', array('uid' => 1001, 'ip' => $_SERVER['REMOTE_ADDR']));
$date = isset($_GET['date']) ? $_GET['date'] : date('Y-m-d');
try {
    foreach ($logger->readLog($date, 50) as $line) {
        echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8') . "<br>\n";
    }
} catch (InvalidArgumentException $e) {
    http_response_code(400);
    echo htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}
