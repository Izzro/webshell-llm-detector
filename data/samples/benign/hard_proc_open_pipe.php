<?php
/**
 * 困难良性样本：使用 proc_open 执行固定 git 命令
 *
 * 业务场景：部署面板显示当前版本的 Git 提交信息。
 *
 * 为什么安全：
 *   1. proc_open 执行的命令 "git" 和参数均硬编码，无用户输入。
 *   2. 仓库路径从环境变量读取，经 realpath + 前缀白名单校验。
 *   3. 命令参数经 escapeshellarg 转义。
 *   4. 仅读取 stdout 管道，git log 是只读操作。
 */

class GitInfoProvider
{
    private $repoPath;
    private $allowed = array('/var/www/', '/srv/projects/', '/home/deploy/');

    public function __construct($repoPath)
    {
        if (empty($repoPath)) $repoPath = getenv('APP_REPO_PATH') ?: '/var/www/app';
        $rp = realpath($repoPath);
        if ($rp === false) throw new InvalidArgumentException("路径不存在");
        $valid = false;
        foreach ($this->allowed as $p) {
            if (strpos($rp, $p) === 0) { $valid = true; break; }
        }
        if (!$valid) throw new InvalidArgumentException("路径不在允许范围");
        $this->repoPath = $rp;
    }

    /** 获取最新提交信息 */
    public function getLatestCommit()
    {
        // 命令和参数完全硬编码
        $args = array('log', '-1', '--pretty=format:%H|%an|%ad|%s', '--date=iso');
        $out = $this->executeGit($args);
        if (empty($out)) throw new RuntimeException('无法获取提交信息');
        $p = explode('|', $out[0], 4);
        if (count($p) < 4) throw new RuntimeException('格式异常');
        return array('hash' => $p[0], 'author' => $p[1], 'date' => $p[2], 'message' => $p[3]);
    }

    /** 执行 git 命令（参数经 escapeshellarg 转义） */
    private function executeGit(array $args)
    {
        $desc = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $cmd = 'git';
        foreach ($args as $a) $cmd .= ' ' . escapeshellarg($a);
        // 限制环境变量，防 PATH 劫持
        $env = array('PATH' => '/usr/bin:/usr/local/bin', 'GIT_DIR' => $this->repoPath . '/.git', 'LANG' => 'C');
        $proc = proc_open($cmd, $desc, $pipes, $this->repoPath, $env);
        if (!is_resource($proc)) throw new RuntimeException('无法启动 git');
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
        $code = proc_close($proc);
        if ($code !== 0) {
            error_log("git 失败: " . $stderr);
            throw new RuntimeException('Git 命令失败');
        }
        return explode("\n", trim($stdout));
    }
}

// 使用示例
try {
    $git = new GitInfoProvider(getenv('APP_REPO_PATH') ?: '');
    $c = $git->getLatestCommit();
    echo "版本: " . htmlspecialchars($c['hash'], ENT_QUOTES, 'UTF-8') . "\n";
    echo "信息: " . htmlspecialchars($c['message'], ENT_QUOTES, 'UTF-8') . "\n";
} catch (Exception $e) {
    echo "错误: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}
