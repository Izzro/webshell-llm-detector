<?php
/**
 * 困难良性样本：调用 clamscan 扫描上传文件
 *
 * 业务场景：文档平台上传附件前调用 ClamAV 病毒扫描。
 *
 * 为什么安全：
 *   1. system() 的文件名参数经过 escapeshellarg() 转义，
 *      被单引号包裹并转义内部单引号，阻止命令注入。
 *   2. 命令主体 "clamscan" 硬编码，不受用户控制。
 *   3. 文件路径经 realpath + 目录归属校验，防路径穿越。
 *   4. exec() 调用完全固定命令，无外部参数。
 */

class VirusScanner
{
    const UPLOAD_DIR = '/var/www/uploads/';

    /**
     * 扫描文件是否含病毒
     * @param string $filename 上传文件名
     * @return array ['clean'=>bool, 'message'=>string]
     */
    public function scan($filename)
    {
        $basename = basename($filename);

        // 文件名白名单校验
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $basename)) {
            return array('clean' => false, 'message' => '文件名含非法字符');
        }

        $filePath = self::UPLOAD_DIR . $basename;

        // 确认文件在上传目录内（防穿越）
        $realPath = realpath($filePath);
        if ($realPath === false || strpos($realPath, realpath(self::UPLOAD_DIR)) !== 0) {
            return array('clean' => false, 'message' => '文件路径非法');
        }

        // 关键安全点：escapeshellarg() 转义路径，防命令注入
        $safePath = escapeshellarg($realPath);
        $command = "clamscan --no-summary --infected " . $safePath;

        $exitCode = 0;
        system($command, $exitCode);

        // clamscan: 0=安全, 1=病毒, 2=错误
        if ($exitCode === 0) {
            return array('clean' => true, 'message' => '文件安全');
        } elseif ($exitCode === 1) {
            return array('clean' => false, 'message' => '检测到病毒');
        }
        return array('clean' => false, 'message' => '扫描器错误');
    }

    /**
     * 获取磁盘信息（命令完全硬编码，无外部参数）
     */
    public function getDiskInfo()
    {
        $output = array();
        exec('df -h /var/www/uploads', $output);
        return implode("\n", $output);
    }
}

// 使用示例
$scanner = new VirusScanner();
$uploadedFile = isset($_FILES['attachment']['name']) ? $_FILES['attachment']['name'] : '';
$result = $scanner->scan($uploadedFile);

if (!$result['clean']) {
    http_response_code(403);
    echo htmlspecialchars($result['message'], ENT_QUOTES, 'UTF-8');
    exit;
}
echo "扫描通过，已保存。\n";
