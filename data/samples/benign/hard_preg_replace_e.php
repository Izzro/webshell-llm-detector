<?php
/**
 * 困难良性样本：安全的 preg_replace 文本处理
 *
 * 业务场景：富文本内容入库前清理：去空白、URL 转链接、敏感信息掩码。
 *
 * 为什么安全：
 *   1. 所有 preg_replace 正则模式均不含 /e 修饰符。
 *      /e 会将替换字符串作为 PHP 代码执行(PHP<7.0)，
 *      本代码使用普通 $1 反向引用，是纯字符串替换。
 *   2. 替换字符串为硬编码字面量，不含用户输入。
 *   3. 用户输入仅作为被处理文本，不进入模式或替换值。
 *   4. 使用 preg_replace_callback 替代 /e 修饰符。
 */

class TextSanitizer
{
    /**
     * 清理富文本内容
     */
    public function sanitize($content)
    {
        if (!is_string($content)) return '';

        $text = strip_tags($content);
        $text = html_entity_decode($text, ENT_QUOTES, 'UTF-8');

        // 以下 preg_replace 均无 /e 修饰符，是安全的正则替换
        $text = preg_replace("/\r\n?/", "\n", $text);       // 统一换行
        $text = preg_replace("/[ \t]+/", " ", $text);        // 压缩空白
        $text = preg_replace("/^[ \t]+|[ \t]+$/m", "", $text); // 去行首尾空白
        $text = preg_replace("/\n{3,}/", "\n\n", $text);     // 压缩连续换行

        return $text;
    }

    /**
     * 将 URL 转换为链接
     * $1 是反向引用，不是代码执行；无 /e 修饰符
     */
    public function linkifyUrls($text)
    {
        $pattern = '/(https?:\/\/[a-zA-Z0-9._~:\/?#\[\]@!$&\'()*+,;=%-]+)/';
        $replacement = '<a href="$1" rel="nofollow" target="_blank">$1</a>';
        return preg_replace($pattern, $replacement, $text);
    }

    /**
     * 将 @username 转换为链接
     * 使用 callback 而非 /e 修饰符
     */
    public function linkifyMentions($text, $baseUri = '/user/')
    {
        $baseUri = filter_var($baseUri, FILTER_SANITIZE_URL) ?: '/user/';
        return preg_replace_callback(
            '/@([a-zA-Z0-9_]{3,20})/',
            function($m) use ($baseUri) {
                $u = htmlspecialchars($m[1], ENT_QUOTES, 'UTF-8');
                $uri = htmlspecialchars($baseUri . $m[1], ENT_QUOTES, 'UTF-8');
                return "<a href=\"{$uri}\">@{$u}</a>";
            },
            $text
        );
    }

    /**
     * 掩码敏感信息（手机号、身份证）
     */
    public function maskSensitive($text)
    {
        // $1/$2 是反向引用，非代码执行
        $text = preg_replace('/(1[3-9]\d)\d{4}(\d{4})/', '$1****$2', $text);
        $text = preg_replace('/(\d{6})\d{8}(\d{4})/', '$1********$2', $text);
        return $text;
    }
}

// 使用示例
$sanitizer = new TextSanitizer();
$input = isset($_POST['content']) ? $_POST['content'] : '';
$clean = $sanitizer->sanitize($input);
$clean = $sanitizer->linkifyUrls($clean);
$clean = $sanitizer->linkifyMentions($clean);
echo $sanitizer->maskSensitive($clean);
