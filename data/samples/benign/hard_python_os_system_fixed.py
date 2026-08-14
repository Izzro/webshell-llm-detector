#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
困难良性样本：使用 os.system 执行固定命令

业务场景：CLI 工具的清屏功能和健康检查脚本。
命令字符串完全硬编码，不含用户输入。

为什么安全：
  1. os.system 参数是硬编码常量（'cls'/'clear'），无外部输入。
  2. ping 目标地址来自白名单，且经 IP 正则校验，
     不可能包含 shell 元字符。
  3. 端口号经 int 转换，只能是数字。
  4. 所有调用不拼接用户可控变量。
"""

import os
import platform
import re


class ConsoleUI:
    """命令行交互界面"""

    IS_WIN = platform.system() == 'Windows'
    CLEAR_CMD = 'cls' if IS_WIN else 'clear'  # 硬编码常量

    @staticmethod
    def clear_screen():
        """清屏 - 命令完全固定，无外部输入"""
        os.system(ConsoleUI.CLEAR_CMD)

    @staticmethod
    def print_header(title):
        ConsoleUI.clear_screen()
        w = len(title) + 4
        print(f"+{'-'*w}+\n|  {title}  |\n+{'-'*w}+")


class HealthChecker:
    """服务健康检查器"""

    PING_TARGETS = ['127.0.0.1', '10.0.0.1', '192.168.1.1', '8.8.8.8']
    IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

    @classmethod
    def _validate_ip(cls, ip):
        """校验 IP 格式，确保不含 shell 元字符"""
        if not isinstance(ip, str) or len(ip) > 15:
            raise ValueError("IP 格式非法")
        m = cls.IP_RE.match(ip)
        if not m:
            raise ValueError(f"IP 不合法: {ip}")
        for seg in m.groups():
            if not (0 <= int(seg) <= 255):
                raise ValueError(f"IP 段超范围: {seg}")
        return True

    @classmethod
    def ping_host(cls, host):
        """Ping 白名单内的主机（host 经 IP 正则 + 白名单双重校验）"""
        cls._validate_ip(host)
        if host not in cls.PING_TARGETS:
            raise ValueError(f"目标不在白名单: {host}")
        # host 经严格校验，仅含数字和点号，安全
        if platform.system() == 'Windows':
            cmd = f'ping -n 2 -w 1000 {host} > nul 2>&1'
        else:
            cmd = f'ping -c 2 -W 1 {host} > /dev/null 2>&1'
        return os.system(cmd) == 0

    @classmethod
    def check_port(cls, port):
        """检查本机端口（端口号经 int 转换，只能是数字）"""
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError("端口必须在 1-65535")
        if platform.system() == 'Windows':
            cmd = f'netstat -an | findstr ":{port} " > nul 2>&1'
        else:
            cmd = f'netstat -tlnp 2>/dev/null | grep ":{port} " > /dev/null 2>&1'
        return os.system(cmd) == 0

if __name__ == '__main__':
    ConsoleUI.print_header("健康检查")
    checker = HealthChecker()
    for host in checker.PING_TARGETS:
        try:
            ok = checker.ping_host(host)
            print(f"  {host:15s} [{'OK' if ok else 'FAIL'}]")
        except ValueError:
            print(f"  {host:15s} [SKIP]")
