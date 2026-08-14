"""
pytest 配置文件

将项目根目录加入 sys.path，使测试可以通过 `from src.xxx import xxx` 导入模块。
"""

import sys
import os

# 获取项目根目录（tests 目录的父目录）
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
